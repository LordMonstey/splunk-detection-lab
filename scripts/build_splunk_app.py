#!/usr/bin/env python3
"""Build a deterministic, self-contained Splunk application archive."""

from __future__ import annotations

import argparse
import configparser
import csv
import gzip
import hashlib
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
from xml.etree import ElementTree

import yaml


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = ROOT / "conf" / "splunk"
DETECTIONS = ROOT / "detections"
APP_ID = "splunk-detection-lab"


def frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise ValueError(f"{path} has no YAML front matter")
    _, payload, _ = text.split("---", 2)
    return yaml.safe_load(payload)


def app_version() -> str:
    parser = configparser.RawConfigParser()
    parser.read(APP_SOURCE / "default" / "app.conf", encoding="utf-8")
    return parser.get("launcher", "version")


def detection_rows() -> list[dict[str, str]]:
    rows = []
    for path in sorted(DETECTIONS.glob("*.md")):
        if path.name == "_template.md":
            continue
        data = frontmatter(path)
        attack = data.get("attack", [])
        if isinstance(attack, dict):
            attack = [attack]
        if isinstance(attack, str):
            attack = [attack]
        techniques = [
            str(item.get("technique", "")) if isinstance(item, dict) else str(item)
            for item in attack
        ]
        techniques = [item for item in techniques if item]
        data_source = data.get("data_source", {})
        if isinstance(data_source, dict):
            data_source_label = " / ".join(
                str(data_source.get(name, "")) for name in ("index", "sourcetype")
                if data_source.get(name)
            )
        else:
            data_source_label = str(data_source)
        schedule = data.get("schedule", {})
        schedule_label = str(schedule.get("cron", "")) if isinstance(schedule, dict) else str(schedule)
        evidence = list((ROOT / "tests" / "atomic" / "evidence").glob("*.png"))
        evidence_count = sum(1 for item in evidence if any(item.name.startswith(t) for t in techniques))
        rows.append(
            {
                "detection_id": str(data["id"]),
                "title": str(data["title"]),
                "status": str(data["status"]).upper(),
                "severity": str(data["severity"]).upper(),
                "risk_score": str(data["risk_score"]),
                "mitre_techniques": ";".join(techniques),
                "data_source": data_source_label,
                "schedule": schedule_label,
                "evidence_count": str(evidence_count),
                "source_path": path.relative_to(ROOT).as_posix(),
            }
        )
    return rows


def write_catalog(path: Path) -> None:
    rows = detection_rows()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def validate_stage(stage: Path) -> None:
    required = (
        "default/app.conf",
        "default/props.conf",
        "default/eventtypes.conf",
        "default/tags.conf",
        "default/datamodels.conf",
        "default/data/models/Security_Telemetry_Qualification.json",
        "default/macros.conf",
        "default/transforms.conf",
        "local/savedsearches.conf",
        "lookups/detection_catalog.csv",
        "metadata/default.meta",
    )
    missing = [name for name in required if not (stage / name).is_file()]
    if missing:
        raise ValueError(f"App staging tree is incomplete: {missing}")

    for xml_file in stage.rglob("*.xml"):
        ElementTree.parse(xml_file)

    forbidden = re.compile(
        r"(?im)^\s*(?:password|passwd|private_key|sessionkey|authorization)\s*[:=]"
    )
    for path in stage.rglob("*"):
        if not path.is_file() or path.suffix.lower() in {".png", ".jpg", ".jpeg"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        match = forbidden.search(text)
        if match:
            raise ValueError(f"Forbidden secret assignment {match.group(0)!r} in {path}")


def manifest(stage: Path, version: str) -> dict:
    files = []
    for path in sorted(item for item in stage.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(stage).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
            }
        )
    return {
        "schema_version": 1,
        "application": APP_ID,
        "version": version,
        "source_date_epoch": 0,
        "detections": len(detection_rows()),
        "files": files,
    }


def normalized_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Remove host metadata so identical sources produce identical archives."""
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    info.mode = 0o755 if info.isdir() else 0o644
    info.pax_headers = {}
    return info


def build(output_dir: Path) -> tuple[Path, Path]:
    version = app_version()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{APP_ID}-{version}.tar.gz"
    manifest_path = output_dir / f"{APP_ID}-{version}.manifest.json"

    with tempfile.TemporaryDirectory(prefix="splunk-app-build-") as temp_dir:
        stage = Path(temp_dir) / APP_ID
        shutil.copytree(APP_SOURCE, stage)
        write_catalog(stage / "lookups" / "detection_catalog.csv")
        validate_stage(stage)
        build_manifest = manifest(stage, version)

        with archive.open("wb") as archive_handle:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=archive_handle,
                mtime=0,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as bundle:
                    bundle.add(stage, arcname=APP_ID, filter=normalized_tarinfo)

    build_manifest["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()

    manifest_path.write_text(
        json.dumps(build_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return archive, manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "build")
    args = parser.parse_args()
    archive, manifest_path = build(args.output)
    print(f"OK: built {archive}")
    print(f"OK: wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
