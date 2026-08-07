#!/usr/bin/env python3
"""Static contract tests for the publishable Linux onboarding scaffold."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "datasets" / "linux"

EXPECTED_FILES = (
    ROOT / "conf" / "splunk" / "default" / "props-linux.conf.example",
    ROOT / "conf" / "splunk" / "default" / "transforms-linux.conf.example",
    ROOT / "conf" / "uf" / "linux-inputs.conf.example",
    DATASET_DIR / "README.md",
    DATASET_DIR / "auditd.log",
    DATASET_DIR / "journald.ndjson",
    DATASET_DIR / "rsyslog.log",
    ROOT / "docs" / "projects" / "linux-security-onboarding.md",
)

DOC_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)

CONF_STANZA = re.compile(r"^\[([^]]+)]$")
CONF_KV = re.compile(r"^([^=\s][^=]*?)\s*=\s*(.*)$")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s<>{}\[\]]+"
)
AUDIT_HEADER = re.compile(
    r"^type=(?P<audit_type>[A-Z0-9_]+)\s+"
    r"msg=audit\((?P<audit_epoch>\d+(?:\.\d+)?):(?P<audit_serial>\d+)\):\s+"
    r"(?P<payload>.*)$"
)
RSYSLOG = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<dest>[A-Za-z0-9_.-]+)\s+"
    r"(?P<app>[A-Za-z0-9_.@/-]+)(?:\[(?P<process_id>\d+)])?:\s+"
    r"(?P<message>.*)$"
)
SSH_AUTH = re.compile(
    r"(?i)^(?P<result>Accepted|Failed)\s+(?P<method>\S+)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src>\S+)\s+"
    r"port\s+(?P<src_port>\d+)"
)
SUDO_CHANGE = re.compile(
    r"^(?P<src_user>\S+)\s*:\s+.*?USER=(?P<user>\S+)\s*;\s+"
    r"COMMAND=(?P<command>.+)$"
)
USERADD = re.compile(r"^new user:\s+name=(?P<user>[^,\s]+),\s+UID=(?P<uid>\d+)")
SYSTEMD = re.compile(
    r"^(?P<state>Started|Stopped|Failed)\s+(?P<service>[^\s]+\.service)\b"
)


class ValidationFailure(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def parse_conf(path: Path) -> dict[str, dict[str, str]]:
    stanzas: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        stanza_match = CONF_STANZA.fullmatch(line)
        if stanza_match:
            name = stanza_match.group(1)
            require(name not in stanzas, f"{path}:{line_number}: duplicate stanza [{name}]")
            current = {}
            stanzas[name] = current
            continue
        kv_match = CONF_KV.fullmatch(line)
        require(current is not None and kv_match is not None, f"{path}:{line_number}: invalid .conf line")
        key = kv_match.group(1).strip()
        require(key not in current, f"{path}:{line_number}: duplicate key {key}")
        current[key] = kv_match.group(2).strip()
    require(bool(stanzas), f"{path}: no stanza found")
    return stanzas


def parse_kv(payload: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in shlex.split(payload, posix=True):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
        if key == "msg":
            fields.update(parse_kv(value))
    return fields


def map_auditd(line: str) -> tuple[str, dict[str, str]]:
    match = AUDIT_HEADER.fullmatch(line)
    require(match is not None, f"auditd line is not parseable: {line}")
    event = match.groupdict()
    event.update(parse_kv(event.pop("payload")))
    audit_type = event["audit_type"]
    result = event.get("res", event.get("success", "unknown"))
    success = result in {"success", "yes", "1"}
    common = {
        "dest": "lab-linux-01",
        "dvc": "lab-linux-01",
        "vendor_product": "Linux auditd",
    }
    if audit_type == "SYSCALL":
        return "Endpoint.Processes", {
            **common,
            "action": "allowed" if success else "blocked",
            "parent_process_id": event.get("ppid", ""),
            "process": event.get("exe", event.get("comm", "")),
            "process_exec": event.get("comm", ""),
            "process_id": event.get("pid", ""),
            "process_name": event.get("comm", ""),
            "process_path": event.get("exe", ""),
            "user": event.get("uid", ""),
        }
    if audit_type == "USER_AUTH":
        return "Authentication", {
            **common,
            "action": "success" if success else "failure",
            "app": Path(event.get("exe", "unknown")).name,
            "authentication_method": "PAM",
            "src": event.get("addr", "unknown"),
            "user": event.get("acct", "unknown"),
        }
    if audit_type in {"USER_MGMT", "CONFIG_CHANGE"}:
        account = event.get("acct", event.get("key", "unknown"))
        return "Change", {
            **common,
            "action": "created" if audit_type == "USER_MGMT" else "modified",
            "change_type": "AAA" if audit_type == "USER_MGMT" else "audit",
            "command": event.get("exe", event.get("op", "unknown")),
            "object_id": event.get("id", event.get("audit_serial", "unknown")),
            "object_path": ("account:" if audit_type == "USER_MGMT" else "audit-rule:") + account,
            "status": "success" if success else "failure",
            "user": account if audit_type == "USER_MGMT" else event.get("auid", "unknown"),
        }
    raise ValidationFailure(f"unmapped audit type: {audit_type}")


def map_journald(line: str) -> tuple[str, dict[str, str]]:
    event = json.loads(line)
    require(isinstance(event, dict), "journald line is not a JSON object")
    for required in ("__REALTIME_TIMESTAMP", "_HOSTNAME", "_SYSTEMD_UNIT", "MESSAGE"):
        require(bool(event.get(required)), f"journald event missing {required}")
    message = str(event["MESSAGE"])
    if re.search(r"(?i)(failed|failure|fatal)", message):
        status = "critical"
    elif re.search(r"(?i)(startup complete|started|starting)", message):
        status = "started"
    elif re.search(r"(?i)(shutdown complete|stopped|stopping)", message):
        status = "stopped"
    else:
        status = "unknown"
    service = str(event["_SYSTEMD_UNIT"])
    return "Endpoint.Services", {
        "dest": str(event["_HOSTNAME"]),
        "service": service,
        "service_name": service.removesuffix(".service"),
        "service_path": str(event.get("_EXE", "unknown")),
        "start_mode": "unknown",
        "status": status,
        "user": str(event.get("_UID", "unknown")),
        "vendor_product": "Linux systemd-journald",
    }


def map_rsyslog(line: str) -> tuple[str, dict[str, str]]:
    match = RSYSLOG.fullmatch(line)
    require(match is not None, f"rsyslog line is not parseable: {line}")
    event = match.groupdict()
    app = event["app"]
    message = event["message"]
    common = {
        "dest": event["dest"],
        "dvc": event["dest"],
        "vendor_product": "Linux rsyslog",
    }
    auth = SSH_AUTH.match(message)
    if app == "sshd" and auth:
        fields = auth.groupdict()
        return "Authentication", {
            **common,
            "action": "success" if fields["result"].lower() == "accepted" else "failure",
            "app": app,
            "authentication_method": fields["method"].lower(),
            "src": fields["src"],
            "user": fields["user"],
        }
    sudo = SUDO_CHANGE.match(message)
    if app == "sudo" and sudo:
        fields = sudo.groupdict()
        return "Change", {
            **common,
            "action": "modified",
            "change_type": "endpoint",
            "command": fields["command"],
            "object_id": fields["command"],
            "object_path": fields["command"],
            "status": "success",
            "user": fields["user"],
        }
    account = USERADD.match(message)
    if app == "useradd" and account:
        fields = account.groupdict()
        return "Change", {
            **common,
            "action": "created",
            "change_type": "AAA",
            "command": "useradd",
            "object_id": fields["uid"],
            "object_path": "account:" + fields["user"],
            "status": "success",
            "user": fields["user"],
        }
    service = SYSTEMD.match(message)
    if app == "systemd" and service:
        fields = service.groupdict()
        state = fields["state"].lower()
        return "Endpoint.Services", {
            **common,
            "service": fields["service"],
            "service_name": fields["service"].removesuffix(".service"),
            "service_path": "unknown",
            "start_mode": "unknown",
            "status": "critical" if state == "failed" else state,
            "user": "0",
        }
    raise ValidationFailure(f"unmapped rsyslog event: {line}")


REQUIRED_FIELDS = {
    "Authentication": {"action", "app", "dest", "user", "vendor_product"},
    "Change": {
        "action",
        "change_type",
        "command",
        "dest",
        "dvc",
        "object_id",
        "object_path",
        "status",
        "user",
        "vendor_product",
    },
    "Endpoint.Processes": {
        "action",
        "dest",
        "parent_process_id",
        "process",
        "process_exec",
        "process_id",
        "process_name",
        "process_path",
        "user",
        "vendor_product",
    },
    "Endpoint.Services": {
        "dest",
        "service",
        "service_name",
        "service_path",
        "start_mode",
        "status",
        "user",
        "vendor_product",
    },
}


def validate_privacy() -> None:
    for path in EXPECTED_FILES:
        text = path.read_text(encoding="utf-8")
        require("-----BEGIN " not in text, f"{path}: embedded PEM material")
        require(not SECRET_ASSIGNMENT.search(text), f"{path}: secret-like assignment")
        for raw_ip in IPV4.findall(text):
            try:
                address = ipaddress.ip_address(raw_ip)
            except ValueError as exc:
                raise ValidationFailure(f"{path}: invalid IPv4 literal {raw_ip}") from exc
            require(
                not any(address in network for network in PRIVATE_NETWORKS),
                f"{path}: private or local address {address}",
            )
            require(
                any(address in network for network in DOC_NETWORKS),
                f"{path}: non-documentation public address {address}",
            )


def validate_configs() -> int:
    props = parse_conf(EXPECTED_FILES[0])
    transforms = parse_conf(EXPECTED_FILES[1])
    inputs = parse_conf(EXPECTED_FILES[2])
    require(set(props) == {"linux:auditd", "linux:journald", "linux:rsyslog"}, "unexpected props stanzas")
    required_transforms = {
        "linux_auditd_header",
        "linux_auditd_result",
        "linux_auditd_account",
        "linux_auditd_operation",
        "linux_auditd_address",
        "linux_rsyslog_header",
        "linux_rsyslog_ssh_auth",
        "linux_rsyslog_sudo",
        "linux_rsyslog_account_change",
        "linux_rsyslog_systemd_service",
    }
    require(required_transforms <= set(transforms), "missing Linux transforms")
    referenced_transforms = {
        value
        for stanza in props.values()
        for key, value in stanza.items()
        if key.startswith("REPORT-")
    }
    require(
        referenced_transforms <= set(transforms),
        "undefined REPORT transform: " + ", ".join(sorted(referenced_transforms - set(transforms))),
    )

    audit_lines = (DATASET_DIR / "auditd.log").read_text(encoding="utf-8").splitlines()
    rsyslog_lines = (DATASET_DIR / "rsyslog.log").read_text(encoding="utf-8").splitlines()
    transform_samples = {
        "linux_auditd_header": audit_lines[0],
        "linux_auditd_result": audit_lines[2],
        "linux_auditd_account": audit_lines[2],
        "linux_auditd_operation": audit_lines[2],
        "linux_auditd_address": audit_lines[2],
        "linux_rsyslog_header": rsyslog_lines[0],
        "linux_rsyslog_ssh_auth": rsyslog_lines[0],
        "linux_rsyslog_sudo": rsyslog_lines[2],
        "linux_rsyslog_account_change": rsyslog_lines[3],
        "linux_rsyslog_systemd_service": rsyslog_lines[4],
    }
    for name, sample in transform_samples.items():
        regex_text = transforms[name].get("REGEX", "")
        format_text = transforms[name].get("FORMAT", "")
        require(bool(regex_text and format_text), f"[{name}] requires REGEX and FORMAT")
        try:
            compiled = re.compile(regex_text)
        except re.error as exc:
            raise ValidationFailure(f"[{name}] invalid REGEX: {exc}") from exc
        require(compiled.search(sample) is not None, f"[{name}] does not match its synthetic contract")
        referenced_groups = [int(value) for value in re.findall(r"\$(\d+)", format_text)]
        require(
            not referenced_groups or max(referenced_groups) <= compiled.groups,
            f"[{name}] FORMAT references an undefined capture group",
        )

    require(inputs["monitor:///var/log/audit/audit.log"].get("disabled") == "0", "auditd input is not active")
    require(inputs["monitor:///var/log/auth.log"].get("disabled") == "0", "auth.log input is not active")
    require(inputs["journald://linux-security-services"].get("disabled") == "0", "journald input is not active")
    for alternative in (
        "monitor:///var/log/secure",
        "monitor:///var/log/syslog",
        "monitor:///var/log/messages",
    ):
        require(inputs[alternative].get("disabled") == "1", f"duplicate-prone alternative enabled: {alternative}")
    for name, stanza in inputs.items():
        require(stanza.get("index") == "os_linux", f"[{name}] has no explicit os_linux index")
        require(stanza.get("sourcetype", "").startswith("linux:"), f"[{name}] has no Linux sourcetype")
    return len(props) + len(transforms) + len(inputs)


def validate_events() -> Counter[str]:
    counters: Counter[str] = Counter()
    parsers = (
        (DATASET_DIR / "auditd.log", map_auditd),
        (DATASET_DIR / "journald.ndjson", map_journald),
        (DATASET_DIR / "rsyslog.log", map_rsyslog),
    )
    for path, parser in parsers:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        require(lines, f"{path}: empty dataset")
        for line_number, line in enumerate(lines, 1):
            try:
                model, fields = parser(line)
            except (ValidationFailure, json.JSONDecodeError, ValueError) as exc:
                raise ValidationFailure(f"{path}:{line_number}: {exc}") from exc
            missing = sorted(
                field for field in REQUIRED_FIELDS[model] if not str(fields.get(field, "")).strip()
            )
            require(not missing, f"{path}:{line_number}: {model} missing {', '.join(missing)}")
            counters[model] += 1
    for model in REQUIRED_FIELDS:
        require(counters[model] > 0, f"no event mapped to {model}")
    return counters


def main() -> int:
    try:
        missing_files = [str(path.relative_to(ROOT)) for path in EXPECTED_FILES if not path.is_file()]
        require(not missing_files, "missing files: " + ", ".join(missing_files))
        stanza_count = validate_configs()
        model_counts = validate_events()
        validate_privacy()
    except ValidationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    total_events = sum(model_counts.values())
    breakdown = ", ".join(f"{model}={model_counts[model]}" for model in sorted(model_counts))
    print(f"OK STATIC: {stanza_count} stanzas, {total_events} synthetic events, {breakdown}")
    print("OK PRIVACY: no embedded secret, private IP, or non-documentation public IP")
    print("LIVE RESULT: not asserted; complete the acceptance table after Splunk replay")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
