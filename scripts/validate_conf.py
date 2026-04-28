#!/usr/bin/env python3
import sys
import re
from pathlib import Path

STANZA = re.compile(r"^\[[^\]]+\]\s*$")
KV     = re.compile(r"^[^=\s]+\s*=\s*.*$")
COMMENT = re.compile(r"^\s*(#|$)")

def validate(path: Path):
    errors = []
    seen_stanzas = set()
    current = None
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if COMMENT.match(line):
            continue
        if STANZA.match(line):
            stanza = line.strip()
            key = (str(path), stanza)
            if key in seen_stanzas:
                errors.append(f"{path}:{i}: duplicate stanza {stanza}")
            seen_stanzas.add(key)
            current = stanza
            continue
        if not KV.match(line):
            errors.append(f"{path}:{i}: not a stanza, comment or key=value: {line!r}")
    return errors

def main():
    paths = list(Path("conf").rglob("*.conf")) + list(Path("macros").rglob("*.conf")) + list(Path("lookups").rglob("*.conf"))
    all_errors = []
    for p in paths:
        all_errors.extend(validate(p))
    if all_errors:
        for e in all_errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print(f"OK: {len(paths)} .conf files validated")

if __name__ == "__main__":
    main()
