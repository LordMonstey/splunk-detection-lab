#!/usr/bin/env python3
"""Render a phase-specific synthetic fixture for the parsing canary drill."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = (ROOT / "artifacts" / "private").resolve()
TEMPLATE = ROOT / "datasets" / "parsing-canary" / "canary-auth.template.log"
RUN_ID = re.compile(r"^parsing-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,16}-(baseline|candidate|rollback)$")


def validate_private_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(PRIVATE_ROOT)
    except ValueError as exc:
        raise ValueError("rendered fixture must remain under artifacts/private") from exc
    return resolved


def render(run_id: str, phase: str, output: Path, event_age_seconds: int) -> tuple[Path, Path]:
    if not RUN_ID.fullmatch(run_id) or not run_id.endswith(f"-{phase}"):
        raise ValueError("run_id must be UTC-stamped, sanitized, and end with the selected phase")
    if not 30 <= event_age_seconds <= 900:
        raise ValueError("event age must remain between 30 and 900 seconds")

    event_time = (datetime.now(timezone.utc) - timedelta(seconds=event_age_seconds)).replace(microsecond=0)
    event_time_text = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    template = TEMPLATE.read_text(encoding="utf-8")
    payload = template.replace("{run_id}", run_id).replace("{event_time}", event_time_text)
    if "{" in payload or "}" in payload:
        raise ValueError("unresolved fixture placeholder")
    lines = [line for line in payload.splitlines() if line]
    if len(lines) != 5 or len(set(lines)) != 5:
        raise ValueError("fixture must contain five unique events")
    if any(not line.endswith("end_marker=CANARY_END") for line in lines):
        raise ValueError("fixture integrity marker is missing")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload.rstrip() + "\n", encoding="utf-8", newline="\n")
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    manifest = {
        "schema_version": 1,
        "provenance": "synthetic-fixture",
        "run_id": run_id,
        "phase": phase,
        "event_time": event_time_text,
        "event_count": len(lines),
        "payload_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "raw_events_in_manifest": False,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output, manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--phase", required=True, choices=("baseline", "candidate", "rollback"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--event-age-seconds", type=int, default=300)
    args = parser.parse_args()
    try:
        output, manifest = render(
            args.run_id,
            args.phase,
            validate_private_output(args.output),
            args.event_age_seconds,
        )
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}")
        return 1
    print(f"PASS: rendered {output}")
    print(f"MANIFEST: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
