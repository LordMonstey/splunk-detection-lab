#!/usr/bin/env python3
"""Assemble private phase aggregates and package facts into the public-evidence input."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = (ROOT / "artifacts" / "private").resolve()
APP_ID = "splunk_parsing_canary_qualification"
PHASES = ("baseline", "candidate", "rollback")
RUN_ID = re.compile(r"^parsing-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,16}$")
SECRET = re.compile(
    r"(?i)(?:password|passwd|token|secret|api[_-]?key|sessionkey|authorization)\s*[:=]"
)


class AssemblyError(ValueError):
    """Raised when private drill material is incomplete or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssemblyError(message)


def private_path(path: Path, *, must_exist: bool = True) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError as exc:
        raise AssemblyError(f"private artifact must remain under {PRIVATE_ROOT}") from exc
    if must_exist:
        require(resolved.is_file(), f"private artifact is missing: {resolved}")
    return resolved


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        decoded = raw.decode("utf-8")
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssemblyError(f"invalid UTF-8 JSON: {path}") from exc
    require(isinstance(payload, dict), f"JSON root must be an object: {path}")
    require("-----BEGIN " not in decoded and SECRET.search(decoded) is None, f"secret-like material found in {path}")
    return payload, raw


def package_facts(path: Path, expected_variant: str, expected_version: str) -> dict[str, str]:
    payload, _ = load_json(path)
    required = {
        "schema_version",
        "app_id",
        "variant",
        "version",
        "promotion_eligible",
        "intended_outcome",
        "scope",
        "archive",
        "archive_sha256",
        "member_count",
        "members",
    }
    require(set(payload) == required, f"package manifest keys mismatch: {path}")
    require(payload["schema_version"] == 1, f"unsupported package manifest schema: {path}")
    require(payload["app_id"] == APP_ID, f"unexpected app ID: {path}")
    require(payload["variant"] == expected_variant, f"unexpected package variant: {path}")
    require(payload["version"] == expected_version, f"unexpected package version: {path}")
    require(
        payload["scope"] == {"index": "idx_recette_parsing", "sourcetype": "canary:auth"},
        f"package scope drift: {path}",
    )
    expected_promotion = expected_variant == "baseline"
    require(payload["promotion_eligible"] is expected_promotion, f"promotion boundary mismatch: {path}")
    archive_sha = payload["archive_sha256"]
    require(isinstance(archive_sha, str) and re.fullmatch(r"[a-f0-9]{64}", archive_sha), f"invalid archive digest: {path}")
    return {"version": expected_version, "archive_sha256": archive_sha}


def effective_config_digest(path: Path) -> tuple[str, bytes]:
    raw = path.read_bytes()
    require(bool(raw.strip()), f"effective configuration capture is empty: {path}")
    decoded = raw.decode("utf-8", errors="strict")
    require("-----BEGIN " not in decoded and SECRET.search(decoded) is None, f"secret-like effective configuration: {path}")
    required_markers = ("canary:auth", "canary_control_fields", "canary_auth_fields")
    require(all(marker in decoded for marker in required_markers), f"effective configuration capture is incomplete: {path}")
    canonical = "\n".join(line.rstrip() for line in decoded.splitlines() if line.strip()) + "\n"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), canonical.encode("utf-8")


def assemble(
    run_id: str,
    started_at: str,
    completed_at: str,
    baseline_manifest: Path,
    candidate_manifest: Path,
    phase_paths: dict[str, Path],
    effective_paths: dict[str, Path],
) -> dict[str, Any]:
    require(RUN_ID.fullmatch(run_id) is not None, "run_id is invalid")
    baseline = package_facts(baseline_manifest, "baseline", "1.0.0")
    candidate = package_facts(candidate_manifest, "candidate", "1.1.0-rc1")
    require(baseline["archive_sha256"] != candidate["archive_sha256"], "candidate archive must differ from baseline")

    phases: dict[str, dict[str, Any]] = {}
    for name in PHASES:
        phase_payload, _ = load_json(phase_paths[name])
        require(phase_payload.get("run_id") == f"{run_id}-{name}", f"{name} phase belongs to another run")
        phases[name] = phase_payload

    config: dict[str, tuple[str, bytes]] = {
        name: effective_config_digest(effective_paths[name]) for name in PHASES
    }
    require(config["baseline"][1] == config["rollback"][1], "rollback effective configuration differs from baseline")
    require(config["baseline"][1] != config["candidate"][1], "candidate effective configuration does not expose the controlled diff")

    return {
        "schema_version": 1,
        "evidence_kind": "live-isolated-lab",
        "run_id": run_id,
        "project": {
            "environment_alias": "lab-parsing-canary",
            "topology": "standalone",
            "index_alias": "idx-recette-parsing",
            "sourcetype_alias": "canary-auth",
            "app_id": APP_ID,
        },
        "change": {
            "started_at": started_at,
            "completed_at": completed_at,
            "controlled_failure": True,
            "execution_mode": "canary-recipe-only",
        },
        "packages": {
            "baseline": {**baseline, "effective_config_sha256": config["baseline"][0]},
            "candidate": {**candidate, "effective_config_sha256": config["candidate"][0]},
            "rollback": {**baseline, "effective_config_sha256": config["rollback"][0]},
        },
        "phases": phases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--baseline-manifest", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    for phase in PHASES:
        parser.add_argument(f"--{phase}-phase", type=Path, required=True)
        parser.add_argument(f"--{phase}-effective", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        baseline_manifest = private_path(args.baseline_manifest)
        candidate_manifest = private_path(args.candidate_manifest)
        phase_paths = {name: private_path(getattr(args, f"{name}_phase")) for name in PHASES}
        effective_paths = {name: private_path(getattr(args, f"{name}_effective")) for name in PHASES}
        output = private_path(args.output, must_exist=False)
        require(not output.exists(), "refusing to overwrite assembled run evidence")
        assembled = assemble(
            args.run_id,
            args.started_at,
            args.completed_at,
            baseline_manifest,
            candidate_manifest,
            phase_paths,
            effective_paths,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(assembled, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeDecodeError, AssemblyError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: assembled private live run {output}")
    print("BOUNDARY: only aggregate metrics and SHA-256 identifiers are eligible for publication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
