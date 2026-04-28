#!/usr/bin/env python3
import sys
from pathlib import Path

def extract(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        sys.exit(f"{path}: missing YAML front-matter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        sys.exit(f"{path}: malformed YAML front-matter")
    return parts[1].strip()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: extract_frontmatter.py <file.md>")
    print(extract(Path(sys.argv[1])))
