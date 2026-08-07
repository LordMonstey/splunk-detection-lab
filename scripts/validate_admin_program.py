#!/usr/bin/env python3
"""Validate the Splunk ES administration program and its shareable evidence."""

from __future__ import annotations

import argparse
import configparser
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree


PROJECT_DOCUMENT = Path("docs/splunk-es-admin-program.md")
DASHBOARD = Path(
    "conf/splunk/local/data/ui/views/splunk_es_admin_operations_center.xml"
)
CONTROL_REGISTER = Path("conf/splunk/lookups/admin_mco_control_register.csv")
NAVIGATION = Path("conf/splunk/local/data/ui/nav/default.xml")
APP_CONF = Path("conf/splunk/default/app.conf")
PLATFORM_ASSURANCE = Path("docs/platform-assurance.md")
PLATFORM_EVIDENCE = Path(
    "artifacts/public/splunk-admin-platform-evidence-20260806.json"
)
CONTINUITY_EVIDENCE = Path(
    "artifacts/public/cluster-resilience-evidence-20260806.json"
)
REQUIRED_RUNBOOKS = {
    Path("docs/runbooks/cluster-mco-resilience.md"),
    Path("docs/runbooks/tls-certificate-lifecycle.md"),
    Path("docs/runbooks/splunk-es-upgrade-rollback.md"),
    Path("docs/enterprise-security-recovery.md"),
    Path("docs/runbooks/troubleshooting-ingestion.md"),
}
EXPECTED_DOMAINS = {
    "Platform",
    "Licensing",
    "Storage",
    "Scheduler",
    "Ingestion",
    "Configuration",
    "Change",
    "TLS",
    "Upgrade",
    "Cluster",
    "Continuity",
    "Reporting",
}
FORBIDDEN_PATTERNS = {
    "private_ipv4": re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
    ),
    "credential_assignment": re.compile(
        r"(?i)\b(?:password|passwd|token|secret)\s*[:=]\s*\S+"
    ),
    "placeholder": re.compile(r"(?i)\b(?:todo|tbd|fixme|lorem ipsum)\b"),
    "unsupported_live_cluster_claim": re.compile(
        r"(?i)\b(?:active|live|operated|production)\s+(?:indexer|search head)?\s*cluster\b"
    ),
}
SEMANTIC_VERSION = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(name: str, passed: bool, detail: str) -> dict[str, object]:
    return {"name": name, "status": "passed" if passed else "failed", "detail": detail}


def required_assets() -> set[Path]:
    return {
        PROJECT_DOCUMENT,
        DASHBOARD,
        CONTROL_REGISTER,
        NAVIGATION,
        APP_CONF,
        PLATFORM_ASSURANCE,
        PLATFORM_EVIDENCE,
        CONTINUITY_EVIDENCE,
        *REQUIRED_RUNBOOKS,
    }


def documented_application_version(text: str) -> str:
    match = re.search(
        r"(?m)^\|\s*Application\s*\|\s*`?([^|`\s]+)`?\s*\|\s*$",
        text,
    )
    return match.group(1) if match else ""


def validate(root: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    required_paths = required_assets()
    missing = sorted(str(path) for path in required_paths if not (root / path).is_file())
    checks.append(check("required_assets", not missing, f"missing={missing}"))
    if missing:
        return build_report(root, checks, {})

    project_text = (root / PROJECT_DOCUMENT).read_text(encoding="utf-8")
    project_numbers = sorted(
        {int(value) for value in re.findall(r"^## Projet (\d+) - ", project_text, re.M)}
    )
    checks.append(
        check(
            "six_independent_projects",
            project_numbers == [1, 2, 3, 4, 5, 6],
            f"projects={project_numbers}",
        )
    )
    sections = re.split(r"(?m)^## Projet \d+ - .+$", project_text)[1:]
    required_subsections = (
        "### Enjeu",
        "### Architecture et realisation",
        "### Livrables",
        "### Validation et resultat",
    )
    complete_projects = sum(
        all(subsection in section for subsection in required_subsections)
        for section in sections[:6]
    )
    checks.append(
        check(
            "project_delivery_contract",
            complete_projects == 6,
            f"complete_projects={complete_projects}/6",
        )
    )

    with (root / CONTROL_REGISTER).open(encoding="utf-8", newline="") as stream:
        controls = list(csv.DictReader(stream))
    domains = {row["domain"] for row in controls}
    unique_controls = {row["control"] for row in controls}
    checks.append(
        check(
            "mco_control_register",
            len(controls) >= 15 and len(unique_controls) == len(controls),
            f"controls={len(controls)} unique={len(unique_controls)}",
        )
    )
    checks.append(
        check(
            "mco_domain_coverage",
            EXPECTED_DOMAINS.issubset(domains),
            f"domains={sorted(domains)}",
        )
    )
    bad_runbook_links = sorted(
        row["runbook"]
        for row in controls
        if not (root / Path(row["runbook"])).is_file()
    )
    checks.append(
        check(
            "control_to_runbook_traceability",
            not bad_runbook_links,
            f"unresolved={bad_runbook_links}",
        )
    )

    dashboard_root = ElementTree.parse(root / DASHBOARD).getroot()
    dashboard_queries = [
        (query.text or "").strip() for query in dashboard_root.findall(".//query")
    ]
    checks.append(
        check(
            "admin_dashboard_structure",
            dashboard_root.tag == "dashboard"
            and dashboard_root.findtext("label") == "Splunk ES Admin Operations Center"
            and len(dashboard_queries) >= 12
            and all(dashboard_queries),
            f"queries={len(dashboard_queries)}",
        )
    )
    required_query_surfaces = (
        "/services/server/info",
        "/services/server/health/splunkd/details",
        "/services/data/indexes",
        "scheduler.log",
        "metrics.log",
        "admin_mco_control_register.csv",
    )
    joined_queries = "\n".join(dashboard_queries)
    missing_surfaces = [
        surface for surface in required_query_surfaces if surface not in joined_queries
    ]
    checks.append(
        check(
            "admin_dashboard_coverage",
            not missing_surfaces,
            f"missing={missing_surfaces}",
        )
    )

    navigation_root = ElementTree.parse(root / NAVIGATION).getroot()
    default_views = [
        view.get("name")
        for view in navigation_root.findall("view")
        if view.get("default") == "true"
    ]
    checks.append(
        check(
            "admin_first_navigation",
            default_views == ["splunk_es_admin_operations_center"],
            f"default={default_views}",
        )
    )

    app_config = configparser.RawConfigParser(interpolation=None)
    app_config.read(root / APP_CONF, encoding="utf-8")
    app_label = app_config.get("ui", "label", fallback="")
    app_visible = app_config.getboolean("ui", "is_visible", fallback=False)
    app_description = app_config.get("launcher", "description", fallback="")
    app_author = app_config.get("launcher", "author", fallback="")
    app_version = app_config.get("launcher", "version", fallback="")
    app_id = app_config.get("package", "id", fallback="")
    app_state = app_config.get("install", "state", fallback="")
    app_configured = app_config.getboolean("install", "is_configured", fallback=False)
    app_build = app_config.get("install", "build", fallback="")
    platform_assurance_text = (root / PLATFORM_ASSURANCE).read_text(encoding="utf-8")
    documented_version = documented_application_version(platform_assurance_text)
    identity_valid = (
        app_label == "Splunk ES Administration"
        and app_description.startswith("Splunk ES administration")
        and app_author == "A.S"
        and app_id == "splunk-detection-lab"
        and app_state == "enabled"
        and app_configured
        and app_visible
        and app_build.isdigit()
        and int(app_build) > 0
    )
    version_valid = bool(SEMANTIC_VERSION.fullmatch(app_version)) and (
        documented_version == app_version
    )
    checks.append(
        check(
            "admin_first_application_identity",
            identity_valid and version_valid,
            f"label={app_label} package={app_id} version={app_version} "
            f"documented_version={documented_version} build={app_build}",
        )
    )

    platform_evidence = json.loads((root / PLATFORM_EVIDENCE).read_text(encoding="utf-8"))
    continuity_evidence = json.loads(
        (root / CONTINUITY_EVIDENCE).read_text(encoding="utf-8")
    )
    platform = platform_evidence.get("platform", {})
    platform_roles = platform.get("roles", {})
    operational_health = platform_evidence.get("operational_health", {})
    monitoring_console = platform_evidence.get("monitoring_console", {})
    continuity_test = platform_evidence.get("continuity_test", {})
    cluster_test = continuity_evidence.get("test", {})
    checks.append(
        check(
            "distributed_platform_evidence",
            platform.get("version") == "10.2.1"
            and platform.get("nodes") == 5
            and platform_roles
            == {
                "cluster_manager": 1,
                "indexer_peers": 2,
                "search_head": 1,
                "monitoring_console": 1,
            }
            and platform.get("unique_server_names") == 5
            and platform.get("unique_instance_guids") == 5
            and platform.get("replication_factor") == 2
            and platform.get("search_factor") == 2,
            f"version={platform.get('version')} nodes={platform.get('nodes')} roles={platform_roles}",
        )
    )
    required_health = (
        "all_peers_are_up",
        "replication_factor_met",
        "search_factor_met",
        "all_data_is_searchable",
        "no_fixup_tasks_in_progress",
        "pre_flight_check",
    )
    checks.append(
        check(
            "cluster_health_evidence",
            all(operational_health.get(key) is True for key in required_health)
            and monitoring_console.get("configured") is True
            and monitoring_console.get("distributed_search_peers_up") == 4
            and monitoring_console.get("roles_inventoried") == 5,
            f"health={all(operational_health.get(key) is True for key in required_health)} "
            f"mc_peers={monitoring_console.get('distributed_search_peers_up')} "
            f"roles={monitoring_console.get('roles_inventoried')}",
        )
    )
    checks.append(
        check(
            "continuity_evidence",
            continuity_test.get("remaining_peer_served_events") == 18812
            and continuity_test.get("all_data_searchable_during_restart") is True
            and continuity_test.get("full_health_recovery_seconds") == 222
            and cluster_test.get("search_continuity", {}).get("events_returned") == 18812
            and cluster_test.get("recovery_duration_seconds") == 222.0
            and cluster_test.get("recovered_health", {}).get("all_peers_are_up") is True,
            f"events={continuity_test.get('remaining_peer_served_events')} "
            f"recovery={continuity_test.get('full_health_recovery_seconds')}s",
        )
    )
    shareable_files = [
        PROJECT_DOCUMENT,
        DASHBOARD,
        CONTROL_REGISTER,
        NAVIGATION,
        APP_CONF,
        PLATFORM_ASSURANCE,
        PLATFORM_EVIDENCE,
        CONTINUITY_EVIDENCE,
        *sorted(REQUIRED_RUNBOOKS),
    ]
    combined_text = "\n".join(
        (root / path).read_text(encoding="utf-8", errors="replace")
        for path in shareable_files
    )
    findings = {
        name: len(pattern.findall(combined_text))
        for name, pattern in FORBIDDEN_PATTERNS.items()
    }
    checks.append(
        check(
            "public_evidence_safety",
            not any(findings.values()),
            json.dumps(findings, sort_keys=True),
        )
    )

    artifacts = {
        str(path): {"sha256": sha256(root / path), "bytes": (root / path).stat().st_size}
        for path in shareable_files
    }
    return build_report(root, checks, artifacts)


def build_report(
    root: Path,
    checks: list[dict[str, object]],
    artifacts: dict[str, object],
) -> dict[str, object]:
    failed = sum(item["status"] != "passed" for item in checks)
    return {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "scope": "splunk-es-admin-program",
        "summary": {
            "checks": len(checks),
            "passed": len(checks) - failed,
            "failed": failed,
            "status": "passed" if failed == 0 else "failed",
        },
        "checks": checks,
        "artifacts": artifacts,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = validate(args.root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    summary = report["summary"]
    print(
        f"{str(summary['status']).upper()}: checks={summary['checks']} "
        f"passed={summary['passed']} failed={summary['failed']} output={args.output}"
    )
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
