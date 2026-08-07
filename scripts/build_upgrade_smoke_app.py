#!/usr/bin/env python3
"""Build the deterministic Splunk upgrade qualification application package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "conf" / "upgrade-smoke-app"
APP_ID = "splunk_upgrade_qualification"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output: Path) -> tuple[Path, Path]:
    files = sorted(path for path in SOURCE.rglob("*") if path.is_file())
    if not files:
        raise ValueError("upgrade smoke app source is empty")
    required = {
        "default/app.conf",
        "default/collections.conf",
        "default/savedsearches.conf",
        "default/data/ui/views/upgrade_qualification.xml",
        "metadata/default.meta",
    }
    relative = {path.relative_to(SOURCE).as_posix() for path in files}
    missing = sorted(required - relative)
    if missing:
        raise ValueError(f"upgrade smoke app is missing: {missing}")

    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{APP_ID}-1.0.0.tar.gz"
    manifest = output / f"{APP_ID}-1.0.0.manifest.json"
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for source in files:
                    relative_name = PurePosixPath(source.relative_to(SOURCE).as_posix())
                    target = str(PurePosixPath(APP_ID) / relative_name)
                    info = tar.gettarinfo(str(source), arcname=target)
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = 0
                    info.mode = 0o644
                    with source.open("rb") as stream:
                        tar.addfile(info, stream)

    payload = {
        "schema_version": 1,
        "app_id": APP_ID,
        "version": "1.0.0",
        "archive": archive.name,
        "archive_sha256": sha256(archive),
        "member_count": len(files),
        "members": [
            {
                "path": str(PurePosixPath(APP_ID) / PurePosixPath(path.relative_to(SOURCE).as_posix())),
                "sha256": sha256(path),
            }
            for path in files
        ],
    }
    manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return archive, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "build")
    args = parser.parse_args()
    archive, manifest = build(args.output)
    print(f"PASS: built {archive}")
    print(f"PASS: wrote {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
