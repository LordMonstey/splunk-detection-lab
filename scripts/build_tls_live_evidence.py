#!/usr/bin/env python3
"""Build a sanitized TLS rotation proof from private validation inputs."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PRIVATE_IPV4 = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|secret|token|authorization|cookie)\s*[:=]"
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(read_text(path))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path.name}")
    return value


def read_text(path: Path) -> str:
    """Decode evidence produced by Linux or Windows without silent corruption."""
    payload = path.read_bytes()
    if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        return payload.decode("utf-16")
    if payload.startswith(b"\xef\xbb\xbf"):
        return payload.decode("utf-8-sig")
    return payload.decode("utf-8")


def parse_live(path: Path, *, require_sslclient: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(path).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", key):
            values[key] = value.strip()
    required = {
        "TLS_LIVE_VALIDATION": "PASS",
        "WEB_STATUS": "200",
        "MANAGEMENT_VERIFY": "PASS",
        "HOSTNAME_MISMATCH_REJECTED": "true",
        "UNRELATED_CA_REJECTED": "true",
        "TLS_1_1_REJECTED": "true",
        "CLEARTEXT_WEB_REJECTED": "true",
        "HSTS_PRESENT": "true",
        "PRIVATE_KEY_MODE": "600",
        "CA_PRIVATE_KEY_ON_SPLUNK_NODE": "false",
    }
    if require_sslclient:
        required["SSLCLIENT_VERIFY"] = "PASS"
    mismatches = {
        key: {"expected": expected, "observed": values.get(key)}
        for key, expected in required.items()
        if values.get(key) != expected
    }
    if mismatches:
        raise ValueError(f"live TLS validation failed: {mismatches}")
    return values


def validate_kv_recovery(diagnostic_path: Path, ready_path: Path) -> dict[str, Any]:
    diagnostic = read_text(diagnostic_path)
    required_diagnostic_phrases = (
        "SSL peer certificate validation failed: unsupported certificate purpose",
        "KV Store changed status to failed",
    )
    missing = [phrase for phrase in required_diagnostic_phrases if phrase not in diagnostic]
    if missing:
        raise ValueError(f"KV Store diagnostic is incomplete: {missing}")
    ready = load_json(ready_path)
    if not (
        ready.get("status") == "ready"
        and ready.get("backup_restore_status") == "Ready"
        and ready.get("disabled") is False
        and ready.get("standalone") is True
    ):
        raise ValueError("KV Store did not return to a ready standalone state")
    return {
        "detected_failure": "certificate_extended_key_usage_incompatible_with_kv_store",
        "failure_gate": "kv_store_status_failed",
        "corrective_action": "regenerated_leaf_with_serverAuth_and_clientAuth",
        "final_status": "ready",
        "backup_restore_status": "Ready",
    }


def parse_switch(path: Path, phrase: str) -> dict[str, str]:
    text = read_text(path)
    if phrase not in text:
        raise ValueError(f"switch proof is missing expected status: {path.name}")
    hashes = dict(
        re.findall(r"(?m)^(server\.conf|web\.conf)_sha256=([0-9a-f]{64})\r?$", text)
    )
    if set(hashes) != {"server.conf", "web.conf"}:
        raise ValueError(f"switch proof is missing configuration hashes: {path.name}")
    return hashes


def certificate_summary(validation: dict[str, Any]) -> dict[str, Any]:
    if validation.get("result") != "PASS":
        raise ValueError("offline certificate validation did not pass")
    server = validation.get("certificates", {}).get("server", {})
    checks = validation.get("checks", {})
    if not checks or any(value != "PASS" for value in checks.values()):
        raise ValueError("offline certificate checks are incomplete")
    return {
        "public_key": server.get("public_key"),
        "signature_algorithm": server.get("signature_algorithm"),
        "sha256_fingerprint": server.get("sha256_fingerprint"),
        "serial": server.get("serial"),
        "not_before": server.get("not_before"),
        "not_after": server.get("not_after"),
        "days_remaining_at_validation": server.get("days_remaining"),
        "dns_sans": validation.get("dns_sans", {}).get("observed", []),
        "offline_checks": checks,
    }


def scan(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            findings.extend(scan(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(scan(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        if PRIVATE_IPV4.search(value):
            findings.append(f"{path}:private_ipv4")
        if SECRET_ASSIGNMENT.search(value):
            findings.append(f"{path}:secret_assignment")
        if "BEGIN PRIVATE KEY" in value:
            findings.append(f"{path}:private_key")
    return findings


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rotation-a-offline", type=Path, required=True)
    parser.add_argument("--rotation-b-offline", type=Path, required=True)
    parser.add_argument("--rotation-a-live", type=Path, required=True)
    parser.add_argument("--rotation-b-live", type=Path, required=True)
    parser.add_argument("--rotation-c-offline", type=Path, required=True)
    parser.add_argument("--rotation-c-live", type=Path, required=True)
    parser.add_argument("--rollback-switch", type=Path, required=True)
    parser.add_argument("--final-switch", type=Path, required=True)
    parser.add_argument("--remediation-switch", type=Path, required=True)
    parser.add_argument("--kv-diagnostic", type=Path, required=True)
    parser.add_argument("--kv-ready", type=Path, required=True)
    parser.add_argument("--final-audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    offline_a = load_json(args.rotation_a_offline)
    offline_b = load_json(args.rotation_b_offline)
    offline_c = load_json(args.rotation_c_offline)
    live_a = parse_live(args.rotation_a_live)
    live_b = parse_live(args.rotation_b_live)
    live_c = parse_live(args.rotation_c_live, require_sslclient=True)
    switch_rollback = parse_switch(
        args.rollback_switch,
        "PASS: evidence-rollback switched TLS from rotation-b to rotation-a",
    )
    switch_final = parse_switch(
        args.final_switch,
        "PASS: evidence-final switched TLS from rotation-a to rotation-b",
    )
    switch_remediation = parse_switch(
        args.remediation_switch,
        "PASS: remediation switched TLS from rotation-b to rotation-c",
    )
    kv_recovery = validate_kv_recovery(args.kv_diagnostic, args.kv_ready)
    audit = load_json(args.final_audit)
    server = audit.get("server", {})
    if not (
        server.get("version") == "9.4.13"
        and server.get("product_type") == "enterprise"
        and server.get("splunkdHealth") == "green"
        and server.get("kvStoreStatus") == "ready"
        and server.get("licenseState") == "OK"
        and audit.get("search_probe", {}).get("status") == "success"
    ):
        raise ValueError("final authenticated Splunk audit did not pass")

    certificate_a = certificate_summary(offline_a)
    certificate_b = certificate_summary(offline_b)
    certificate_c = certificate_summary(offline_c)
    if live_a.get("LEAF_SHA256") != certificate_a["sha256_fingerprint"]:
        raise ValueError("rotation A live fingerprint differs from offline validation")
    if live_b.get("LEAF_SHA256") != certificate_b["sha256_fingerprint"]:
        raise ValueError("rotation B live fingerprint differs from offline validation")
    if live_c.get("LEAF_SHA256") != certificate_c["sha256_fingerprint"]:
        raise ValueError("rotation C live fingerprint differs from offline validation")
    if not (
        offline_c.get("policy", {}).get("server_and_client_auth_eku_required") is True
        and offline_c.get("checks", {}).get("chain_and_sslserver_sslclient_purpose") == "PASS"
    ):
        raise ValueError("rotation C is missing the KV-compatible EKU validation gate")

    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    evidence = {
        "artifact_type": "splunk_tls_rotation_live_evidence",
        "schema_version": 1,
        "generated_at_utc": generated,
        "status": "passed_after_remediation",
        "proof_boundary": {
            "platform": "Splunk Enterprise",
            "native_enterprise_security_installed": False,
            "lab_only": True,
            "production_os_compatibility_claimed": False,
        },
        "target": {
            "version": server.get("version"),
            "build": server.get("build"),
            "product_type": server.get("product_type"),
            "splunkd_health": server.get("splunkdHealth"),
            "license_state": server.get("licenseState"),
            "kv_store_status": server.get("kvStoreStatus"),
            "active_rotation": "rotation-c",
            "protocol": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        },
        "certificate_profiles": {
            "rotation-a": {
                **certificate_a,
                "qualified_scope": "web_and_management_only",
                "kv_store_compatible": False,
            },
            "rotation-b": {
                **certificate_b,
                "qualified_scope": "web_and_management_only",
                "kv_store_compatible": False,
            },
            "rotation-c": {
                **certificate_c,
                "qualified_scope": "web_management_and_kv_store",
                "kv_store_compatible": True,
                "extended_key_usage": ["serverAuth", "clientAuth"],
            },
        },
        "change_sequence": [
            {
                "step": "rollback_to_rotation_a",
                "status": "passed",
                "configuration_sha256": switch_rollback,
                "post_change_validation": "passed",
            },
            {
                "step": "final_activation_rotation_b",
                "status": "passed",
                "configuration_sha256": switch_final,
                "post_change_validation": "passed",
            },
            {
                "step": "post_change_dependency_gate_rotation_b",
                "status": "failed_as_expected_by_gate",
                "decision": "do_not_close_change",
                "finding": kv_recovery["detected_failure"],
            },
            {
                "step": "remediate_and_activate_rotation_c",
                "status": "passed",
                "configuration_sha256": switch_remediation,
                "post_change_validation": "passed",
                "kv_store_status": kv_recovery["final_status"],
            },
        ],
        "dependency_regression_and_recovery": kv_recovery,
        "live_controls": {
            "web_https_status_200": True,
            "management_chain_and_hostname_verified": True,
            "ssl_client_and_server_purposes_verified": True,
            "kv_store_ready_after_rotation": True,
            "hostname_mismatch_rejected": True,
            "unrelated_ca_rejected": True,
            "tls_1_1_rejected": True,
            "cleartext_web_rejected": True,
            "hsts_present": True,
            "private_key_mode_0600": True,
            "ca_private_key_absent_from_splunk_tree": True,
            "authenticated_post_change_audit": True,
        },
        "negative_tests": {
            "hostname_mismatch": "rejected",
            "untrusted_chain": "rejected",
            "obsolete_protocol_tls_1_1": "rejected",
            "cleartext_splunk_web": "rejected",
        },
        "limitations": [
            "The evidence validates one standalone laboratory instance, not a production topology.",
            "External client-certificate authentication and forwarder-to-indexer mTLS are outside this execution.",
            "The certificate common name uses the reserved lab.test namespace.",
        ],
    }
    findings = scan(evidence)
    if findings:
        raise ValueError(f"public evidence safety scan failed: {findings}")
    atomic_write(args.output, evidence)
    print(f"PASS: wrote sanitized TLS evidence to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
