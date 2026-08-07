#!/usr/bin/env python3
"""Validate public Splunk TLS certificates without network access or secrets."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


PEM_BEGIN = b"-----BEGIN "
PRIVATE_KEY_MARKERS = tuple(
    PEM_BEGIN + label + b"-----"
    for label in (
        b"PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
    )
)
FQDN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


class ValidationError(RuntimeError):
    """Raised when certificate material violates the validation policy."""


def run_openssl(openssl: str, arguments: Sequence[str], *, check: bool = True) -> str:
    process = subprocess.run(
        [openssl, *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip() or "unknown OpenSSL error"
        raise ValidationError(f"OpenSSL rejected the certificate material: {detail}")
    return process.stdout.strip()


def validate_public_pem(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ValidationError(f"{label} must not be a symbolic link")
    if not path.is_file():
        raise ValidationError(f"{label} is not a regular file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValidationError(f"{label} exceeds the 2 MiB safety limit")

    payload = path.read_bytes()
    if any(marker in payload for marker in PRIVATE_KEY_MARKERS):
        raise ValidationError(f"{label} contains private-key material")
    if payload.count(PEM_BEGIN + b"CERTIFICATE-----") != 1:
        raise ValidationError(f"{label} must contain exactly one PEM certificate")

    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValidationError(f"{label} must not be group- or world-writable")


def openssl_field(openssl: str, path: Path, *arguments: str) -> str:
    return run_openssl(openssl, ["x509", "-in", str(path), "-noout", *arguments])


def parse_single_value(output: str, field: str) -> str:
    prefix = f"{field}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    raise ValidationError(f"OpenSSL output is missing {field}")


def parse_openssl_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValidationError(f"Unsupported OpenSSL certificate date: {value}") from error


def certificate_summary(openssl: str, path: Path) -> dict[str, Any]:
    fingerprint_output = openssl_field(openssl, path, "-fingerprint", "-sha256")
    fingerprint = fingerprint_output.split("=", 1)[-1].strip().upper()
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", fingerprint):
        raise ValidationError("Malformed SHA-256 certificate fingerprint")

    dates = openssl_field(openssl, path, "-dates")
    not_before = parse_openssl_time(parse_single_value(dates, "notBefore"))
    not_after = parse_openssl_time(parse_single_value(dates, "notAfter"))
    now = datetime.now(timezone.utc)

    return {
        "filename": path.name,
        "sha256_fingerprint": fingerprint,
        "serial": parse_single_value(openssl_field(openssl, path, "-serial"), "serial"),
        "subject": parse_single_value(
            openssl_field(openssl, path, "-subject", "-nameopt", "RFC2253"), "subject"
        ),
        "issuer": parse_single_value(
            openssl_field(openssl, path, "-issuer", "-nameopt", "RFC2253"), "issuer"
        ),
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "days_remaining": max(0, int((not_after - now).total_seconds() // 86400)),
    }


def validate_key_strength(certificate_text: str) -> dict[str, Any]:
    lowered = certificate_text.lower()
    if "id-ecpublickey" in lowered or "ec public key" in lowered:
        match = re.search(r"Public-Key:\s*\((\d+) bit\)", certificate_text)
        bits = int(match.group(1)) if match else 0
        if bits < 256:
            raise ValidationError(f"EC public key is below 256 bits ({bits})")
        return {"algorithm": "EC", "bits": bits}

    if "rsaencryption" in lowered or "rsa public-key" in lowered:
        match = re.search(r"Public-Key:\s*\((\d+) bit\)", certificate_text)
        bits = int(match.group(1)) if match else 0
        if bits < 3072:
            raise ValidationError(f"RSA public key is below 3072 bits ({bits})")
        return {"algorithm": "RSA", "bits": bits}

    raise ValidationError("Unsupported or unrecognized public-key algorithm")


def validate_signature_algorithm(certificate_text: str) -> str:
    algorithms = re.findall(r"Signature Algorithm:\s*([^\r\n]+)", certificate_text)
    if not algorithms:
        raise ValidationError("Certificate signature algorithm is missing")
    normalized = {algorithm.strip() for algorithm in algorithms}
    if any("sha1" in algorithm.lower() or "md5" in algorithm.lower() for algorithm in normalized):
        raise ValidationError("SHA-1 and MD5 certificate signatures are forbidden")
    return sorted(normalized)[0]


def validate_dns_name(value: str) -> None:
    if len(value) > 253 or ".." in value or not FQDN_RE.fullmatch(value):
        raise ValidationError(f"Expected DNS SAN is not a non-wildcard FQDN: {value}")


def collect_sans(openssl: str, server_certificate: Path) -> list[str]:
    output = openssl_field(openssl, server_certificate, "-ext", "subjectAltName")
    if "IP Address:" in output:
        raise ValidationError("IP SANs are forbidden by this public-evidence policy")
    names = re.findall(r"DNS:([^,\s]+)", output)
    if not names:
        raise ValidationError("Server certificate has no DNS SAN")
    if any("*" in name for name in names):
        raise ValidationError("Wildcard DNS SANs are forbidden by this policy")
    for name in names:
        validate_dns_name(name)
    return names


def validate_certificate_extensions(
    openssl: str, ca_certificate: Path, server_certificate: Path
) -> None:
    ca_basic = openssl_field(openssl, ca_certificate, "-ext", "basicConstraints")
    ca_usage = openssl_field(openssl, ca_certificate, "-ext", "keyUsage")
    server_basic = openssl_field(openssl, server_certificate, "-ext", "basicConstraints")
    server_usage = openssl_field(openssl, server_certificate, "-ext", "keyUsage")
    server_extended = openssl_field(openssl, server_certificate, "-ext", "extendedKeyUsage")

    if "CA:TRUE" not in ca_basic.replace(" ", ""):
        raise ValidationError("CA certificate is missing CA:TRUE")
    if "Certificate Sign" not in ca_usage or "CRL Sign" not in ca_usage:
        raise ValidationError("CA certificate key usage must include certificate and CRL signing")
    if "CA:FALSE" not in server_basic.replace(" ", ""):
        raise ValidationError("Server certificate is missing CA:FALSE")
    if "Digital Signature" not in server_usage:
        raise ValidationError("Server certificate key usage must include Digital Signature")
    has_server_auth = (
        "TLS Web Server Authentication" in server_extended or "serverAuth" in server_extended
    )
    has_client_auth = (
        "TLS Web Client Authentication" in server_extended or "clientAuth" in server_extended
    )
    if not has_server_auth:
        raise ValidationError("Server certificate EKU must include TLS Web Server Authentication")
    if not has_client_auth:
        raise ValidationError(
            "Splunk inter-component certificate EKU must include TLS Web Client Authentication"
        )


def validate_certificates(arguments: argparse.Namespace) -> dict[str, Any]:
    openssl = arguments.openssl or shutil.which("openssl")
    if not openssl:
        raise ValidationError("OpenSSL was not found; use --openssl with an explicit executable")

    ca_certificate = arguments.ca_cert.expanduser()
    server_certificate = arguments.server_cert.expanduser()
    validate_public_pem(ca_certificate, "CA certificate")
    validate_public_pem(server_certificate, "server certificate")

    expected_dns = list(dict.fromkeys(arguments.expected_dns))
    if not expected_dns:
        raise ValidationError("At least one --expected-dns value is required")
    for name in expected_dns:
        validate_dns_name(name)

    run_openssl(
        openssl,
        [
            "verify",
            "-purpose",
            "sslserver",
            "-CAfile",
            str(ca_certificate),
            str(server_certificate),
        ],
    )
    run_openssl(
        openssl,
        [
            "verify",
            "-purpose",
            "sslclient",
            "-CAfile",
            str(ca_certificate),
            str(server_certificate),
        ],
    )

    check_seconds = arguments.min_validity_days * 86400
    for certificate_label, certificate_path in (
        ("CA", ca_certificate),
        ("server", server_certificate),
    ):
        check_result = subprocess.run(
            [
                openssl,
                "x509",
                "-in",
                str(certificate_path),
                "-noout",
                "-checkend",
                str(check_seconds),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if check_result.returncode != 0:
            raise ValidationError(
                f"{certificate_label} certificate expires within "
                f"{arguments.min_validity_days} days"
            )

    observed_dns = collect_sans(openssl, server_certificate)
    expected_set = {name.lower() for name in expected_dns}
    observed_set = {name.lower() for name in observed_dns}
    if arguments.allow_extra_san:
        missing = expected_set - observed_set
        if missing:
            raise ValidationError(f"Missing expected DNS SANs: {', '.join(sorted(missing))}")
    elif expected_set != observed_set:
        missing = expected_set - observed_set
        unexpected = observed_set - expected_set
        details = []
        if missing:
            details.append(f"missing={','.join(sorted(missing))}")
        if unexpected:
            details.append(f"unexpected={','.join(sorted(unexpected))}")
        raise ValidationError(f"DNS SAN set mismatch ({'; '.join(details)})")

    validate_certificate_extensions(openssl, ca_certificate, server_certificate)
    ca_text = run_openssl(openssl, ["x509", "-in", str(ca_certificate), "-noout", "-text"])
    server_text = run_openssl(
        openssl, ["x509", "-in", str(server_certificate), "-noout", "-text"]
    )
    ca_key = validate_key_strength(ca_text)
    server_key = validate_key_strength(server_text)
    ca_signature = validate_signature_algorithm(ca_text)
    server_signature = validate_signature_algorithm(server_text)

    ca_summary = certificate_summary(openssl, ca_certificate)
    server_summary = certificate_summary(openssl, server_certificate)
    if ca_summary["subject"] != ca_summary["issuer"]:
        raise ValidationError("Root CA certificate must be self-issued")
    if server_summary["subject"] == server_summary["issuer"]:
        raise ValidationError("Server certificate must not be self-issued")
    if server_summary["issuer"] != ca_summary["subject"]:
        raise ValidationError("Server issuer does not match the supplied root CA subject")
    if server_summary["sha256_fingerprint"] == ca_summary["sha256_fingerprint"]:
        raise ValidationError("Server and CA certificate fingerprints must differ")
    if int(server_summary["serial"], 16) == 0 or int(ca_summary["serial"], 16) == 0:
        raise ValidationError("Certificate serial numbers must be non-zero")
    ca_not_after = datetime.fromisoformat(ca_summary["not_after"].replace("Z", "+00:00"))
    server_not_after = datetime.fromisoformat(
        server_summary["not_after"].replace("Z", "+00:00")
    )
    if server_not_after > ca_not_after:
        raise ValidationError("Server certificate outlives its issuing CA")

    return {
        "schema_version": 1,
        "validated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "openssl_version": run_openssl(openssl, ["version"]),
        "policy": {
            "offline_only": True,
            "private_key_material_forbidden": True,
            "ip_san_forbidden": True,
            "wildcard_san_forbidden": True,
            "minimum_validity_days": arguments.min_validity_days,
            "minimum_ec_bits": 256,
            "minimum_rsa_bits": 3072,
            "server_and_client_auth_eku_required": True,
        },
        "checks": {
            "chain_and_sslserver_sslclient_purpose": "PASS",
            "validity_window": "PASS",
            "dns_san_policy": "PASS",
            "basic_constraints": "PASS",
            "key_usage": "PASS",
            "signature_algorithm": "PASS",
        },
        "dns_sans": {
            "expected": sorted(expected_dns, key=str.lower),
            "observed": sorted(observed_dns, key=str.lower),
            "exact_match_required": not arguments.allow_extra_san,
        },
        "certificates": {
            "ca": {
                **ca_summary,
                "public_key": ca_key,
                "signature_algorithm": ca_signature,
            },
            "server": {
                **server_summary,
                "public_key": server_key,
                "signature_algorithm": server_signature,
            },
        },
        "result": "PASS",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline validation of public Splunk TLS certificates. "
            "The report contains only certificate metadata and SHA-256 fingerprints."
        )
    )
    parser.add_argument("--ca-cert", type=Path, required=True, help="Public root CA PEM")
    parser.add_argument("--server-cert", type=Path, required=True, help="Public leaf PEM")
    parser.add_argument(
        "--expected-dns",
        action="append",
        default=[],
        help="Expected non-wildcard DNS SAN; repeat for every exact SAN",
    )
    parser.add_argument(
        "--min-validity-days",
        type=int,
        default=30,
        help="Fail if the server certificate expires within this many days (default: 30)",
    )
    parser.add_argument(
        "--allow-extra-san",
        action="store_true",
        help="Require expected SANs but permit additional DNS SANs",
    )
    parser.add_argument("--openssl", help="Explicit OpenSSL executable")
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Create a new JSON evidence file; an existing file is never overwritten",
    )
    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()
    if arguments.min_validity_days < 0 or arguments.min_validity_days > 3650:
        parser.error("--min-validity-days must be between 0 and 3650")

    try:
        report = validate_certificates(arguments)
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if arguments.json_output:
            output = arguments.json_output.expanduser()
            if output.is_symlink():
                raise ValidationError("JSON output must not be a symbolic link")
            output.parent.mkdir(parents=False, exist_ok=True)
            with output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(serialized)
        sys.stdout.write(serialized)
        return 0
    except (OSError, ValidationError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
