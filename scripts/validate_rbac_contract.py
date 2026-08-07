#!/usr/bin/env python3
"""Validate the publishable Splunk 9.4.13 to 10.2.1 RBAC contract offline."""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import re
import sys
from pathlib import Path


AUTHORIZE = Path("conf/splunk/default/authorize.conf.example")
MATRIX = Path("conf/splunk/lookups/rbac_access_matrix.csv")
DOCUMENT = Path("docs/projects/splunk-rbac-governance.md")

ROLES = (
    "platform_admin",
    "platform_operator",
    "detection_engineer",
    "soc_analyst",
    "audit_reader",
    "api_health",
)
ROLE_COLUMNS = list(ROLES)

ROLE_SETTINGS = {
    "srchIndexesAllowed",
    "srchIndexesDefault",
    "srchIndexesDisallowed",
    "srchJobsQuota",
    "rtSrchJobsQuota",
    "srchDiskQuota",
    "srchTimeWin",
    "srchTimeEarliest",
    "cumulativeSrchJobsQuota",
    "cumulativeRTSrchJobsQuota",
    "importRoles",
    "grantableRoles",
}
REQUIRED_SETTINGS = {
    "srchIndexesAllowed",
    "srchIndexesDefault",
    "srchJobsQuota",
    "rtSrchJobsQuota",
    "srchDiskQuota",
    "srchTimeWin",
    "srchTimeEarliest",
    "cumulativeSrchJobsQuota",
    "cumulativeRTSrchJobsQuota",
}
POSITIVE_INTEGER_SETTINGS = {
    "srchJobsQuota",
    "rtSrchJobsQuota",
    "srchDiskQuota",
    "srchTimeWin",
    "srchTimeEarliest",
    "cumulativeSrchJobsQuota",
    "cumulativeRTSrchJobsQuota",
}

SEARCH_BASE = {
    "change_own_password",
    "get_metadata",
    "get_typeahead",
    "list_inputs",
    "request_remote_tok",
    "rest_apps_view",
    "rest_properties_get",
    "search",
}
EXPECTED_CAPABILITIES = {
    "platform_admin": SEARCH_BASE
    | {
        "edit_deployment_client",
        "edit_deployment_server",
        "edit_dist_peer",
        "edit_forwarders",
        "edit_health",
        "edit_httpauths",
        "edit_indexer_cluster",
        "edit_indexerdiscovery",
        "edit_input_defaults",
        "edit_local_apps",
        "edit_modinput_journald",
        "edit_monitor",
        "edit_search_head_clustering",
        "edit_search_server",
        "edit_server",
        "edit_sourcetypes",
        "edit_splunktcp",
        "edit_splunktcp_ssl",
        "edit_tcp",
        "edit_token_http",
        "edit_udp",
        "edit_web_settings",
        "indexes_edit",
        "install_apps",
        "license_edit",
        "license_read",
        "license_tab",
        "license_view_warnings",
        "list_deployment_client",
        "list_deployment_server",
        "list_dist_peer",
        "list_forwarders",
        "list_health",
        "list_health_subset",
        "list_indexer_cluster",
        "list_indexerdiscovery",
        "list_introspection",
        "list_remote_input_queue",
        "list_remote_output_queue",
        "list_search_head_clustering",
        "list_search_scheduler",
        "list_settings",
        "list_token_http",
        "rest_access_server_endpoints",
        "rest_properties_set",
        "restart_splunkd",
        "search_process_config_refresh",
    },
    "platform_operator": SEARCH_BASE
    | {
        "license_read",
        "license_tab",
        "license_view_warnings",
        "list_deployment_client",
        "list_deployment_server",
        "list_dist_peer",
        "list_forwarders",
        "list_health",
        "list_health_subset",
        "list_indexer_cluster",
        "list_indexerdiscovery",
        "list_introspection",
        "list_remote_input_queue",
        "list_remote_output_queue",
        "list_search_head_clustering",
        "list_search_scheduler",
        "list_settings",
        "rest_access_server_endpoints",
    },
    "detection_engineer": SEARCH_BASE
    | {
        "accelerate_datamodel",
        "accelerate_search",
        "edit_log_alert_event",
        "edit_own_objects",
        "edit_search_schedule_priority",
        "edit_search_schedule_window",
        "list_accelerate_search",
        "output_file",
        "run_sendalert",
        "schedule_search",
    },
    "soc_analyst": SEARCH_BASE | {"edit_own_objects"},
    "audit_reader": (SEARCH_BASE - {"list_inputs"})
    | {"list_all_roles", "list_all_users"},
    "api_health": {
        "license_read",
        "license_view_warnings",
        "list_deployment_client",
        "list_dist_peer",
        "list_forwarders",
        "list_health",
        "list_health_subset",
        "list_indexer_cluster",
        "list_introspection",
        "list_remote_input_queue",
        "list_remote_output_queue",
        "list_search_head_clustering",
        "list_search_scheduler",
        "list_settings",
        "rest_access_server_endpoints",
        "rest_apps_view",
        "rest_properties_get",
    },
}

IMPLICIT_DEFAULT_CAPABILITIES_TO_DISABLE = {
    role: {
        "list_all_objects",
        "run_collect",
        "run_mcollect",
        "schedule_rtsearch",
        *({"edit_own_objects"} if role not in {"detection_engineer", "soc_analyst"} else set()),
    }
    for role in ROLES
}

# Official authorize.conf specifications were compared for every capability in
# the original 71-capability draft. These four capabilities are present in
# Splunk Enterprise 10.2.1 but absent from 9.4.13, so the common baseline must
# not assign them. The remaining 67 unique capabilities are available in both
# versions and are rechecked against the live capability endpoint before apply.
SPLUNK_9_4_13_INCOMPATIBLE_CAPABILITIES = {
    "edit_certificates",
    "edit_saved_search",
    "list_certificates",
    "list_saved_searches",
}
EXPECTED_COMMON_CAPABILITY_COUNT = 67

EXPECTED_INDEXES = {
    "platform_admin": {
        "allowed": {
            "main",
            "summary",
            "windows",
            "sysmon",
            "os_linux",
            "risk",
            "notable",
            "_internal",
            "_audit",
            "_introspection",
            "_telemetry",
        },
        "default": {"_internal", "_audit"},
    },
    "platform_operator": {
        "allowed": {"summary", "_internal", "_introspection", "_telemetry"},
        "default": {"_internal", "_introspection"},
    },
    "detection_engineer": {
        "allowed": {"windows", "sysmon", "os_linux", "risk", "notable", "summary"},
        "default": {"windows", "sysmon", "os_linux", "risk", "notable"},
    },
    "soc_analyst": {
        "allowed": {"windows", "sysmon", "os_linux", "risk", "notable", "summary"},
        "default": {"windows", "sysmon", "os_linux", "risk", "notable"},
    },
    "audit_reader": {"allowed": {"_audit"}, "default": {"_audit"}},
    "api_health": {"allowed": {"_internal"}, "default": {"_internal"}},
}

DANGEROUS_CAPABILITIES = {
    "admin_all_objects",
    "change_authentication",
    "delete_by_keyword",
    "edit_roles",
    "edit_roles_grantable",
    "edit_scripted",
    "edit_storage_passwords",
    "edit_tokens_all",
    "edit_user",
    "list_storage_passwords",
    "list_tokens_all",
    "rtsearch",
    "run_custom_command",
    "run_debug_commands",
    "schedule_rtsearch",
}

MATRIX_HEADERS = [
    "control_id",
    "domain",
    "interface",
    "method",
    "target",
    "required_control",
    *ROLE_COLUMNS,
]
EXPECTED_MATRIX_RIGHTS = {
    "RBAC-001": {"platform_admin", "detection_engineer", "soc_analyst"},
    "RBAC-002": {"platform_admin", "platform_operator"},
    "RBAC-003": {"platform_admin", "audit_reader"},
    "RBAC-004": {"platform_admin", "platform_operator", "api_health"},
    "RBAC-005": {"platform_admin", "platform_operator", "api_health"},
    "RBAC-006": {"platform_admin", "platform_operator", "api_health"},
    "RBAC-007": set(),
    "RBAC-008": set(),
    "RBAC-009": {"platform_admin"},
    "RBAC-010": {"platform_admin"},
    "RBAC-011": {"platform_admin", "platform_operator"},
    "RBAC-012": {"platform_admin"},
    "RBAC-013": {"detection_engineer", "soc_analyst"},
    "RBAC-014": {"detection_engineer"},
    "RBAC-015": {"detection_engineer"},
    "RBAC-016": {"detection_engineer"},
    "RBAC-017": {"audit_reader"},
    "RBAC-018": set(),
    "RBAC-019": set(),
    "RBAC-020": set(),
}
CONTROL_REQUIREMENTS = {
    "RBAC-001": ("search", "security"),
    "RBAC-002": ("search", "_internal"),
    "RBAC-003": ("search", "_audit"),
    "RBAC-004": ("rest_access_server_endpoints", "list_health"),
    "RBAC-005": ("list_indexer_cluster",),
    "RBAC-006": ("license_read",),
    "RBAC-007": ("cross_version_excluded",),
    "RBAC-008": ("cross_version_excluded",),
    "RBAC-009": ("indexes_edit",),
    "RBAC-010": ("restart_splunkd",),
    "RBAC-011": ("list_deployment_server",),
    "RBAC-012": ("edit_deployment_server",),
    "RBAC-013": ("edit_own_objects",),
    "RBAC-014": ("schedule_search",),
    "RBAC-015": ("accelerate_datamodel", "edit_own_objects"),
    "RBAC-016": ("output_file",),
    "RBAC-017": ("list_all_users", "list_all_roles"),
    "RBAC-018": ("edit_user",),
    "RBAC-019": ("edit_roles",),
    "RBAC-020": ("rtsearch",),
}

FORBIDDEN_PATTERNS = {
    "private_ipv4": re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
    ),
    "credential_assignment": re.compile(
        r"(?i)\b(?:password|passwd|secret|token)\s*[:=]\s*[^\s$<>{}]+"
    ),
    "placeholder": re.compile(r"(?i)\b(?:todo|tbd|fixme|lorem ipsum)\b"),
}


def split_semicolon(value: str) -> set[str]:
    return {item.strip() for item in value.split(";") if item.strip()}


def result(name: str, passed: bool, detail: str) -> dict[str, object]:
    return {"name": name, "status": "passed" if passed else "failed", "detail": detail}


def load_authorize(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with path.open(encoding="utf-8") as stream:
        parser.read_file(stream)
    return parser


def capabilities(parser: configparser.ConfigParser, role: str) -> set[str]:
    section = parser[f"role_{role}"]
    return {key for key, value in section.items() if key not in ROLE_SETTINGS and value == "enabled"}


def requirement_met(
    parser: configparser.ConfigParser, role: str, requirements: tuple[str, ...]
) -> bool:
    role_capabilities = capabilities(parser, role)
    allowed_indexes = split_semicolon(
        parser[f"role_{role}"].get("srchIndexesAllowed", "")
    )
    for requirement in requirements:
        if requirement == "security":
            if not {"windows", "sysmon", "os_linux", "risk", "notable"}.issubset(
                allowed_indexes
            ):
                return False
        elif requirement.startswith("_"):
            if requirement not in allowed_indexes:
                return False
        elif requirement not in role_capabilities:
            return False
    return True


def validate(root: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    paths = [root / AUTHORIZE, root / MATRIX, root / DOCUMENT]
    missing = [str(path.relative_to(root)) for path in paths if not path.is_file()]
    checks.append(result("required_assets", not missing, f"missing={missing}"))
    if missing:
        return {"status": "failed", "checks": checks}

    try:
        parser = load_authorize(root / AUTHORIZE)
        parse_error = ""
    except (OSError, configparser.Error) as exc:
        parser = configparser.ConfigParser()
        parse_error = str(exc)
    checks.append(result("authorize_syntax", not parse_error, parse_error or "valid INI"))
    if parse_error:
        return {"status": "failed", "checks": checks}

    actual_sections = set(parser.sections())
    expected_sections = {f"role_{role}" for role in ROLES}
    checks.append(
        result(
            "role_inventory",
            actual_sections == expected_sections,
            f"roles={sorted(actual_sections)}",
        )
    )

    missing_settings: dict[str, list[str]] = {}
    invalid_values: list[str] = []
    imported_roles: list[str] = []
    wildcard_roles: list[str] = []
    index_drift: list[str] = []
    capability_drift: list[str] = []
    default_override_drift: list[str] = []
    dangerous: list[str] = []
    for role in ROLES:
        section_name = f"role_{role}"
        if section_name not in parser:
            continue
        section = parser[section_name]
        missing_for_role = sorted(REQUIRED_SETTINGS - set(section))
        if missing_for_role:
            missing_settings[role] = missing_for_role
        if "importRoles" in section or "grantableRoles" in section:
            imported_roles.append(role)
        for setting in POSITIVE_INTEGER_SETTINGS:
            try:
                if int(section.get(setting, "0")) <= 0:
                    invalid_values.append(f"{role}:{setting}")
            except ValueError:
                invalid_values.append(f"{role}:{setting}")
        allowed = split_semicolon(section.get("srchIndexesAllowed", ""))
        defaults = split_semicolon(section.get("srchIndexesDefault", ""))
        disallowed = split_semicolon(section.get("srchIndexesDisallowed", ""))
        if any("*" in item for item in allowed | defaults | disallowed):
            wildcard_roles.append(role)
        if defaults - allowed or allowed & disallowed:
            invalid_values.append(f"{role}:index_scope")
        if allowed != EXPECTED_INDEXES[role]["allowed"] or defaults != EXPECTED_INDEXES[role]["default"]:
            index_drift.append(role)

        actual_capabilities = capabilities(parser, role)
        invalid_capability_values = sorted(
            key
            for key, value in section.items()
            if key not in ROLE_SETTINGS and value not in {"enabled", "disabled"}
        )
        if invalid_capability_values:
            invalid_values.extend(
                f"{role}:{key}" for key in invalid_capability_values
            )
        if actual_capabilities != EXPECTED_CAPABILITIES[role]:
            missing_caps = sorted(EXPECTED_CAPABILITIES[role] - actual_capabilities)
            extra_caps = sorted(actual_capabilities - EXPECTED_CAPABILITIES[role])
            capability_drift.append(
                f"{role}:missing={missing_caps}:extra={extra_caps}"
            )
        actual_disabled = {
            key
            for key, value in section.items()
            if key not in ROLE_SETTINGS and value == "disabled"
        }
        if actual_disabled != IMPLICIT_DEFAULT_CAPABILITIES_TO_DISABLE[role]:
            default_override_drift.append(
                f"{role}:missing={sorted(IMPLICIT_DEFAULT_CAPABILITIES_TO_DISABLE[role] - actual_disabled)}:"
                f"extra={sorted(actual_disabled - IMPLICIT_DEFAULT_CAPABILITIES_TO_DISABLE[role])}"
            )
        dangerous_for_role = sorted(actual_capabilities & DANGEROUS_CAPABILITIES)
        if dangerous_for_role:
            dangerous.append(f"{role}:{dangerous_for_role}")

    checks.append(result("complete_role_settings", not missing_settings, str(missing_settings)))
    checks.append(result("no_role_inheritance", not imported_roles, f"roles={imported_roles}"))
    checks.append(result("bounded_quotas", not invalid_values, f"invalid={invalid_values}"))
    checks.append(result("explicit_index_scopes", not wildcard_roles, f"wildcards={wildcard_roles}"))
    checks.append(result("index_contract", not index_drift, f"drift={index_drift}"))
    checks.append(result("capability_contract", not capability_drift, f"drift={capability_drift}"))
    checks.append(
        result(
            "implicit_default_capability_overrides",
            not default_override_drift,
            f"drift={default_override_drift}",
        )
    )
    checks.append(result("dangerous_capabilities_absent", not dangerous, f"found={dangerous}"))
    declared_capabilities = set().union(
        *(capabilities(parser, role) for role in ROLES if f"role_{role}" in parser)
    )
    incompatible_declared = sorted(
        declared_capabilities & SPLUNK_9_4_13_INCOMPATIBLE_CAPABILITIES
    )
    checks.append(
        result(
            "splunk_9_4_13_to_10_2_1_capability_baseline",
            not incompatible_declared
            and len(declared_capabilities) == EXPECTED_COMMON_CAPABILITY_COUNT,
            f"unique={len(declared_capabilities)}:incompatible={incompatible_declared}",
        )
    )

    with (root / MATRIX).open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        headers = reader.fieldnames or []
    checks.append(result("matrix_schema", headers == MATRIX_HEADERS, f"headers={headers}"))
    ids = [row.get("control_id", "") for row in rows]
    checks.append(
        result(
            "matrix_inventory",
            set(ids) == set(EXPECTED_MATRIX_RIGHTS) and len(ids) == len(set(ids)),
            f"controls={ids}",
        )
    )

    invalid_cells: list[str] = []
    rights_drift: list[str] = []
    requirement_drift: list[str] = []
    for row in rows:
        control_id = row.get("control_id", "")
        if control_id not in EXPECTED_MATRIX_RIGHTS:
            continue
        allowed_by_matrix: set[str] = set()
        for role in ROLES:
            raw_value = row.get(role, "")
            if raw_value != raw_value.strip() or raw_value not in {"ALLOW", "DENY"}:
                invalid_cells.append(f"{control_id}:{role}:{raw_value!r}")
            if raw_value == "ALLOW":
                allowed_by_matrix.add(role)
            expected_by_config = requirement_met(parser, role, CONTROL_REQUIREMENTS[control_id])
            if (raw_value == "ALLOW") != expected_by_config:
                requirement_drift.append(
                    f"{control_id}:{role}:matrix={raw_value}:config={expected_by_config}"
                )
        if allowed_by_matrix != EXPECTED_MATRIX_RIGHTS[control_id]:
            rights_drift.append(
                f"{control_id}:actual={sorted(allowed_by_matrix)}:"
                f"expected={sorted(EXPECTED_MATRIX_RIGHTS[control_id])}"
            )
    checks.append(result("matrix_cell_values", not invalid_cells, f"invalid={invalid_cells}"))
    checks.append(result("matrix_rights_contract", not rights_drift, f"drift={rights_drift}"))
    checks.append(
        result(
            "matrix_to_authorize_traceability",
            not requirement_drift,
            f"drift={requirement_drift}",
        )
    )

    document_text = (root / DOCUMENT).read_text(encoding="utf-8")
    required_headings = (
        "# Gouvernance RBAC Splunk Enterprise 9.4.13 à 10.2.1",
        "## Statut de la preuve",
        "## Configuration cible",
        "## Modèle de rôles",
        "## Déploiement contrôlé",
        "## Tests positifs",
        "## Tests négatifs",
        "## Rollback",
        "## Registre de preuve live",
    )
    missing_headings = [heading for heading in required_headings if heading not in document_text]
    checks.append(result("documentation_contract", not missing_headings, f"missing={missing_headings}"))
    evidence_separation = (
        "CONFIGURATION CIBLE ET PERSISTANTE" in document_text
        and "PREUVE LIVE EXÉCUTÉE - RÉUSSIE" in document_text
        and "rbac-live-evidence-9.4.13-20260807.json" in document_text
        and str(AUTHORIZE).replace("\\", "/") in document_text
        and str(MATRIX).replace("\\", "/") in document_text
    )
    checks.append(
        result(
            "target_vs_live_separation",
            evidence_separation,
            "target and live status are explicitly separated",
        )
    )

    scan_findings: list[str] = []
    for path in (AUTHORIZE, MATRIX, DOCUMENT):
        text = (root / path).read_text(encoding="utf-8")
        for name, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(text):
                scan_findings.append(f"{path}:{name}")
    checks.append(result("public_safety_scan", not scan_findings, f"findings={scan_findings}"))

    passed = sum(item["status"] == "passed" for item in checks)
    return {
        "status": "passed" if passed == len(checks) else "failed",
        "summary": {"passed": passed, "total": len(checks)},
        "checks": checks,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (defaults to the parent of scripts/).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = validate(args.root.resolve())
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for item in report["checks"]:
            marker = "PASS" if item["status"] == "passed" else "FAIL"
            print(f"[{marker}] {item['name']}: {item['detail']}")
        summary = report.get("summary", {})
        print(f"RBAC contract: {report['status']} ({summary.get('passed', 0)}/{summary.get('total', len(report['checks']))})")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
