#!/usr/bin/env python3
import sys
import re
from pathlib import Path

try:
    import yaml
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "pyyaml"])
    import yaml

REQUIRED_TOP_LEVEL = {
    "id", "title", "status", "author", "created", "modified",
    "severity", "risk_score", "attack", "data_source", "schedule",
}
ALLOWED_STATUS = {"experimental", "testing", "production", "deprecated"}
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}
ID_PATTERN = re.compile(r"^(win|lin|net)_[a-z]+_t\d{4}(\.\d{3})?_[a-z0-9_-]+$")

def parse(path: Path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    _, fm, _ = text.split("---", 2)
    return yaml.safe_load(fm)

def main():
    detections = sorted(Path("detections").glob("*.md"))
    errors = []
    for f in detections:
        if f.name == "_template.md":
            continue
        try:
            data = parse(f)
        except Exception as e:
            errors.append(f"{f}: cannot parse YAML ({e})")
            continue
        if data is None:
            errors.append(f"{f}: no YAML front-matter")
            continue
        missing = REQUIRED_TOP_LEVEL - set(data.keys())
        if missing:
            errors.append(f"{f}: missing fields: {sorted(missing)}")
        if data.get("status") not in ALLOWED_STATUS:
            errors.append(f"{f}: invalid status {data.get('status')!r}")
        if data.get("severity") not in ALLOWED_SEVERITY:
            errors.append(f"{f}: invalid severity {data.get('severity')!r}")
        if "id" in data and not ID_PATTERN.match(str(data["id"])):
            errors.append(f"{f}: id does not match naming convention")
        if "id" in data and f.stem != data["id"]:
            errors.append(f"{f}: filename does not match id field ({data['id']})")
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print(f"OK: {len(detections)-1} detections validated")

if __name__ == "__main__":
    main()
