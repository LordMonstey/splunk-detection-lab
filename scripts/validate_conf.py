#!/usr/bin/env python3
import sys
import re
from pathlib import Path

STANZA = re.compile(r"^\[[^\]]+\]\s*$")
KV     = re.compile(r"^[^=\s]+\s*=\s*.*$")
COMMENT = re.compile(r"^\s*(#|$)")
MACRO_REF = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)(?:\([^`]*\))?`")
LOOKUP_REF = re.compile(r"\|\s*lookup\s+([A-Za-z_][A-Za-z0-9_]*)")

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


def macro_names(path: Path):
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = STANZA.match(line)
        if not match:
            continue
        name = line.strip()[1:-1]
        names.add(re.sub(r"\(\d+\)$", "", name))
    return names


def lookup_definitions(path: Path):
    definitions = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if STANZA.match(line):
            current = line.strip()[1:-1]
            definitions[current] = {}
            continue
        if current is None or not KV.match(line):
            continue
        key, value = line.split("=", 1)
        definitions[current][key.strip()] = value.strip()
    return definitions


def validate_saved_search_references():
    errors = []
    macros_path = Path("macros/macros.conf")
    searches_path = Path("conf/splunk/local/savedsearches.conf")
    transforms_path = Path("conf/splunk/local/transforms.conf")

    defined_macros = macro_names(macros_path)
    search_text = searches_path.read_text(encoding="utf-8")
    referenced_macros = set(MACRO_REF.findall(search_text))
    for name in sorted(referenced_macros - defined_macros):
        errors.append(f"{searches_path}: undefined macro `{name}`")

    definitions = lookup_definitions(transforms_path)
    for name in sorted(set(LOOKUP_REF.findall(search_text))):
        definition = definitions.get(name)
        if definition is None or "filename" not in definition:
            errors.append(
                f"{searches_path}: lookup {name!r} is not registered "
                f"with a filename in {transforms_path}"
            )
            continue
        csv_path = Path("lookups") / definition["filename"]
        if not csv_path.is_file():
            errors.append(
                f"{transforms_path}: lookup {name!r} references missing "
                f"file {csv_path}"
            )

    return errors


def main():
    paths = list(Path("conf").rglob("*.conf")) + list(Path("macros").rglob("*.conf")) + list(Path("lookups").rglob("*.conf"))
    all_errors = []
    for p in paths:
        all_errors.extend(validate(p))
    all_errors.extend(validate_saved_search_references())
    if all_errors:
        for e in all_errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    print(f"OK: {len(paths)} .conf files validated")

if __name__ == "__main__":
    main()
