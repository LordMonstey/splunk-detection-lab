#!/usr/bin/env python3
"""Build deterministic baseline and controlled-failure parsing canary packages."""

from __future__ import annotations

import argparse
import configparser
import gzip
import hashlib
import ipaddress
import json
import re
import tarfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "conf" / "parsing-canary"
APP_ID = "splunk_parsing_canary_qualification"
VARIANTS = {
    "baseline": {
        "version": "1.0.0",
        "promotion_eligible": True,
        "intended_outcome": "conformant-baseline",
    },
    "candidate": {
        "version": "1.1.0-rc1",
        "promotion_eligible": False,
        "intended_outcome": "controlled-no-go",
    },
}
REQUIRED_MEMBERS = {
    "default/app.conf",
    "default/indexes.conf",
    "default/props.conf",
    "default/transforms.conf",
    "metadata/default.meta",
}
ALLOWED_VARIANT_DIFFS = {
    "default/app.conf",
    "default/props.conf",
    "default/transforms.conf",
}
SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:password|passwd|token|secret|private_key|sessionkey|authorization)\s*[:=]"
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


class PackageError(ValueError):
    """Raised when the canary package contract is violated."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def relative_files(source: Path) -> dict[str, Path]:
    return {
        path.relative_to(source).as_posix(): path
        for path in sorted(source.rglob("*"))
        if path.is_file()
    }


def read_conf(path: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    parser.optionxform = str
    with path.open(encoding="utf-8") as stream:
        parser.read_file(stream)
    return parser


def validate_text_security(path: Path, text: str) -> None:
    if "-----BEGIN " in text or SECRET_ASSIGNMENT.search(text):
        raise PackageError(f"secret-like material is forbidden in {path}")
    for literal in IPV4.findall(text):
        try:
            address = ipaddress.ip_address(literal)
        except ValueError as exc:
            raise PackageError(f"invalid IPv4 literal {literal} in {path}") from exc
        if any(address in network for network in PRIVATE_NETWORKS):
            raise PackageError(f"private address {address} is forbidden in {path}")


def validate_variant(variant: str) -> dict[str, Path]:
    expected = VARIANTS[variant]
    source = SOURCE_ROOT / variant
    files = relative_files(source)
    missing = sorted(REQUIRED_MEMBERS - set(files))
    unexpected = sorted(set(files) - REQUIRED_MEMBERS)
    if missing or unexpected:
        raise PackageError(f"{variant}: missing={missing}, unexpected={unexpected}")

    for relative, path in files.items():
        validate_text_security(path, path.read_text(encoding="utf-8"))

    app_conf = read_conf(files["default/app.conf"])
    if app_conf.get("launcher", "version") != expected["version"]:
        raise PackageError(f"{variant}: unexpected app version")
    if app_conf.get("ui", "is_visible") != "0":
        raise PackageError(f"{variant}: qualification app must remain hidden")

    indexes = read_conf(files["default/indexes.conf"])
    if indexes.sections() != ["idx_recette_parsing"]:
        raise PackageError(f"{variant}: package must own only idx_recette_parsing")

    props = read_conf(files["default/props.conf"])
    if props.sections() != ["canary:auth"]:
        raise PackageError(f"{variant}: package must affect only canary:auth")
    stanza = props["canary:auth"]
    if stanza.get("REPORT-canary-control") != "canary_control_fields":
        raise PackageError(f"{variant}: immutable control extraction is missing")
    if stanza.get("REPORT-canary-auth") != "canary_auth_fields":
        raise PackageError(f"{variant}: application-field extraction is missing")
    if stanza.get("KV_MODE") != "none":
        raise PackageError(f"{variant}: automatic key-value extraction would invalidate the negative control")

    transforms = read_conf(files["default/transforms.conf"])
    if transforms.sections() != ["canary_control_fields", "canary_auth_fields"]:
        raise PackageError(f"{variant}: unexpected transform stanza")

    if variant == "baseline":
        if stanza.get("TIME_PREFIX") != r"\bevent_time=":
            raise PackageError("baseline: timestamp contract is not conformant")
        if stanza.get("DATETIME_CONFIG", "").upper() == "CURRENT":
            raise PackageError("baseline: CURRENT timestamp mode is forbidden")
        if "src=" not in transforms.get("canary_auth_fields", "REGEX"):
            raise PackageError("baseline: src extraction is not conformant")
    else:
        if stanza.get("TIME_PREFIX") != r"\boccurred_at=":
            raise PackageError("candidate: controlled timestamp regression is missing")
        if stanza.get("DATETIME_CONFIG") != "CURRENT":
            raise PackageError("candidate: deterministic CURRENT timestamp regression is missing")
        if "source_ip=" not in transforms.get("canary_auth_fields", "REGEX"):
            raise PackageError("candidate: controlled src regression is missing")
    return files


def validate_variant_boundary(baseline: dict[str, Path], candidate: dict[str, Path]) -> None:
    changed = {
        relative
        for relative in REQUIRED_MEMBERS
        if baseline[relative].read_bytes() != candidate[relative].read_bytes()
    }
    if changed != ALLOWED_VARIANT_DIFFS:
        raise PackageError(f"unexpected baseline/candidate diff boundary: {sorted(changed)}")
    if baseline["default/indexes.conf"].read_bytes() != candidate["default/indexes.conf"].read_bytes():
        raise PackageError("candidate must not change the recipe index")
    if baseline["metadata/default.meta"].read_bytes() != candidate["metadata/default.meta"].read_bytes():
        raise PackageError("candidate must not change permissions or export scope")


def normalized_tarinfo(path: Path, arcname: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(arcname)
    data = path.read_bytes()
    info.size = len(data)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    info.mode = 0o644
    info.pax_headers = {}
    return info


def build_variant(variant: str, files: dict[str, Path], output: Path) -> tuple[Path, Path]:
    metadata = VARIANTS[variant]
    version = str(metadata["version"])
    archive = output / f"{APP_ID}-{variant}-{version}.tar.gz"
    manifest_path = output / f"{APP_ID}-{variant}-{version}.manifest.json"

    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
                for relative, source in sorted(files.items()):
                    arcname = str(PurePosixPath(APP_ID) / PurePosixPath(relative))
                    data = source.read_bytes()
                    bundle.addfile(normalized_tarinfo(source, arcname), fileobj=_BytesReader(data))

    members = [
        {
            "path": str(PurePosixPath(APP_ID) / PurePosixPath(relative)),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        for relative, path in sorted(files.items())
    ]
    manifest = {
        "schema_version": 1,
        "app_id": APP_ID,
        "variant": variant,
        "version": version,
        "promotion_eligible": metadata["promotion_eligible"],
        "intended_outcome": metadata["intended_outcome"],
        "scope": {"index": "idx_recette_parsing", "sourcetype": "canary:auth"},
        "archive": archive.name,
        "archive_sha256": sha256_file(archive),
        "member_count": len(members),
        "members": members,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return archive, manifest_path


class _BytesReader:
    """Minimal binary reader accepted by TarFile.addfile without extra dependencies."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


def build(output: Path) -> dict[str, tuple[Path, Path]]:
    files = {variant: validate_variant(variant) for variant in VARIANTS}
    validate_variant_boundary(files["baseline"], files["candidate"])
    output.mkdir(parents=True, exist_ok=True)
    return {
        variant: build_variant(variant, files[variant], output)
        for variant in ("baseline", "candidate")
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "private" / "parsing-canary" / "build")
    args = parser.parse_args()
    try:
        outputs = build(args.output.resolve())
    except (OSError, configparser.Error, PackageError) as error:
        print(f"FAIL: {error}")
        return 1
    for variant, (archive, manifest) in outputs.items():
        print(f"PASS {variant}: {archive}")
        print(f"MANIFEST {variant}: {manifest}")
    print("BOUNDARY: idx_recette_parsing / canary:auth only; candidate is not promotion eligible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
