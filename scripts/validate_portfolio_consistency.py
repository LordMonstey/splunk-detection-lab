#!/usr/bin/env python3
"""Cross-check the portfolio against the repository sources of truth."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit(
        "PyYAML is required. Install the pinned development dependency with "
        "`python -m pip install PyYAML==6.0.3`."
    )


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"
SAVED_SEARCHES = ROOT / "conf" / "splunk" / "local" / "savedsearches.conf"
INDEXES_CONF = ROOT / "conf" / "splunk" / "local" / "indexes.conf"
PORTFOLIO_DATA = ROOT / "site" / "portfolio-data.js"
SNAPSHOT = ROOT / "artifacts" / "public" / "splunk-snapshot-20260725.json"

EXPECTED_DETECTION_COUNT = 18
TACTIC_ALIASES = {
    "command-control": "command-and-control",
}


@dataclass(frozen=True)
class Detection:
    path: Path
    frontmatter: dict[str, Any]
    spl: str


class JSDataParseError(ValueError):
    """Raised when portfolio-data.js is not a static data assignment."""


class JSDataParser:
    """Parse the JSON-compatible JavaScript literal assigned to LAB_DATA.

    The portfolio data file intentionally contains only objects, arrays,
    strings, numbers, booleans and null. Parsing that subset avoids evaluating
    repository JavaScript in CI.
    """

    _IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
    _NUMBER = re.compile(
        r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
    )

    def __init__(self, source: str) -> None:
        self.source = source
        self.position = 0

    def parse_assignment(self) -> dict[str, Any]:
        self._skip_ignored()
        assignment = re.match(
            r"window\s*\.\s*LAB_DATA\s*=",
            self.source[self.position :],
        )
        if assignment is None:
            self._fail("expected `window.LAB_DATA =` assignment")
        self.position += assignment.end()
        value = self._parse_value()
        self._skip_ignored()
        if self._peek() == ";":
            self.position += 1
        self._skip_ignored()
        if self.position != len(self.source):
            self._fail("unexpected code after LAB_DATA assignment")
        if not isinstance(value, dict):
            self._fail("LAB_DATA must be an object")
        return value

    def _parse_value(self) -> Any:
        self._skip_ignored()
        current = self._peek()
        if current == "{":
            return self._parse_object()
        if current == "[":
            return self._parse_array()
        if current in {'"', "'"}:
            return self._parse_string()
        number = self._NUMBER.match(self.source, self.position)
        if number is not None:
            self.position = number.end()
            token = number.group(0)
            return float(token) if any(char in token for char in ".eE") else int(token)
        identifier = self._parse_identifier()
        literals = {"true": True, "false": False, "null": None}
        if identifier in literals:
            return literals[identifier]
        self._fail(f"unsupported value {identifier!r}")

    def _parse_object(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        self._expect("{")
        self._skip_ignored()
        if self._peek() == "}":
            self.position += 1
            return result
        while True:
            self._skip_ignored()
            if self._peek() in {'"', "'"}:
                key = self._parse_string()
            else:
                key = self._parse_identifier()
            if not isinstance(key, str) or not key:
                self._fail("object key must be a non-empty string")
            if key in result:
                self._fail(f"duplicate object key {key!r}")
            self._skip_ignored()
            self._expect(":")
            result[key] = self._parse_value()
            self._skip_ignored()
            current = self._peek()
            if current == "}":
                self.position += 1
                return result
            self._expect(",")
            self._skip_ignored()
            if self._peek() == "}":
                self.position += 1
                return result

    def _parse_array(self) -> list[Any]:
        result: list[Any] = []
        self._expect("[")
        self._skip_ignored()
        if self._peek() == "]":
            self.position += 1
            return result
        while True:
            result.append(self._parse_value())
            self._skip_ignored()
            current = self._peek()
            if current == "]":
                self.position += 1
                return result
            self._expect(",")
            self._skip_ignored()
            if self._peek() == "]":
                self.position += 1
                return result

    def _parse_string(self) -> str:
        quote = self._peek()
        self.position += 1
        result: list[str] = []
        escapes = {
            "'": "'",
            '"': '"',
            "\\": "\\",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "v": "\v",
            "0": "\0",
        }
        while self.position < len(self.source):
            current = self.source[self.position]
            self.position += 1
            if current == quote:
                return "".join(result)
            if current in "\r\n":
                self._fail("unescaped newline in string")
            if current != "\\":
                result.append(current)
                continue
            if self.position >= len(self.source):
                self._fail("unterminated string escape")
            escaped = self.source[self.position]
            self.position += 1
            if escaped in escapes:
                result.append(escapes[escaped])
            elif escaped == "x":
                result.append(chr(self._parse_hex_escape(2)))
            elif escaped == "u":
                result.append(chr(self._parse_hex_escape(4)))
            elif escaped == "\n":
                continue
            elif escaped == "\r":
                if self._peek() == "\n":
                    self.position += 1
            else:
                # JavaScript treats an unrecognised escape as the escaped
                # character itself. The data file normally doubles such
                # backslashes, but matching the language keeps parsing exact.
                result.append(escaped)
        self._fail("unterminated string")

    def _parse_hex_escape(self, length: int) -> int:
        end = self.position + length
        token = self.source[self.position : end]
        if len(token) != length or not re.fullmatch(r"[0-9A-Fa-f]+", token):
            self._fail("invalid hexadecimal string escape")
        self.position = end
        return int(token, 16)

    def _parse_identifier(self) -> str:
        match = self._IDENTIFIER.match(self.source, self.position)
        if match is None:
            self._fail("expected identifier")
        self.position = match.end()
        return match.group(0)

    def _skip_ignored(self) -> None:
        while True:
            while self.position < len(self.source) and self.source[
                self.position
            ].isspace():
                self.position += 1
            if self.source.startswith("//", self.position):
                newline = self.source.find("\n", self.position + 2)
                self.position = len(self.source) if newline == -1 else newline + 1
                continue
            if self.source.startswith("/*", self.position):
                end = self.source.find("*/", self.position + 2)
                if end == -1:
                    self._fail("unterminated block comment")
                self.position = end + 2
                continue
            return

    def _expect(self, token: str) -> None:
        self._skip_ignored()
        if not self.source.startswith(token, self.position):
            self._fail(f"expected {token!r}")
        self.position += len(token)

    def _peek(self) -> str:
        if self.position >= len(self.source):
            return ""
        return self.source[self.position]

    def _fail(self, message: str) -> None:
        line = self.source.count("\n", 0, self.position) + 1
        column = self.position - self.source.rfind("\n", 0, self.position)
        raise JSDataParseError(f"line {line}, column {column}: {message}")


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def normalize_spl(value: str) -> str:
    """Collapse formatting whitespace outside quoted SPL string literals."""

    result: list[str] = []
    quote: str | None = None
    escaped = False
    pending_space = False
    for current in value.strip():
        if quote is not None:
            result.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
            continue
        if current in {'"', "'"}:
            if (
                pending_space
                and result
                and result[-1] not in {" ", "(", ","}
            ):
                result.append(" ")
            pending_space = False
            quote = current
            result.append(current)
        elif current.isspace():
            pending_space = True
        elif current in {"(", ")", ","}:
            if result and result[-1] == " ":
                result.pop()
            result.append(current)
            pending_space = False
        else:
            if (
                pending_space
                and result
                and result[-1] not in {" ", "(", ","}
            ):
                result.append(" ")
            pending_space = False
            result.append(current)
    return "".join(result).strip()


def parse_conf(path: Path, errors: list[str]) -> dict[str, dict[str, str]]:
    stanzas: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        stanza_match = re.fullmatch(r"\[([^\]]+)\]", line)
        if stanza_match:
            current = stanza_match.group(1)
            if current in stanzas:
                errors.append(
                    f"{display_path(path)}:{line_number}: duplicate stanza "
                    f"[{current}]"
                )
            stanzas.setdefault(current, {})
            continue
        if current is None or "=" not in raw_line:
            errors.append(
                f"{display_path(path)}:{line_number}: invalid line outside a stanza"
            )
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip()
        if key in stanzas[current]:
            errors.append(
                f"{display_path(path)}:{line_number}: duplicate key {key!r} "
                f"in [{current}]"
            )
        stanzas[current][key] = value.strip()
    return stanzas


def load_detections(errors: list[str]) -> dict[str, Detection]:
    detections: dict[str, Detection] = {}
    for path in sorted(DETECTIONS_DIR.glob("*.md")):
        if path.name == "_template.md":
            continue
        text = path.read_text(encoding="utf-8")
        parts = text.split("---", 2)
        if len(parts) != 3 or parts[0].strip():
            errors.append(f"{display_path(path)}: invalid YAML frontmatter delimiters")
            continue
        try:
            frontmatter = yaml.safe_load(parts[1])
        except yaml.YAMLError as exc:
            errors.append(f"{display_path(path)}: invalid YAML ({exc})")
            continue
        if not isinstance(frontmatter, dict):
            errors.append(f"{display_path(path)}: frontmatter must be an object")
            continue
        logic_blocks = re.findall(
            r"```spl[ \t]*\r?\n(.*?)\r?\n```",
            parts[2],
            flags=re.DOTALL,
        )
        if len(logic_blocks) != 1:
            errors.append(
                f"{display_path(path)}: expected exactly one fenced SPL logic "
                f"block, found {len(logic_blocks)}"
            )
            continue
        detection_id = frontmatter.get("id")
        if not isinstance(detection_id, str) or not detection_id:
            errors.append(f"{display_path(path)}: missing string id")
            continue
        if detection_id in detections:
            errors.append(f"{display_path(path)}: duplicate id {detection_id!r}")
            continue
        detections[detection_id] = Detection(
            path=path,
            frontmatter=frontmatter,
            spl=logic_blocks[0],
        )
    return detections


def load_portfolio_data(errors: list[str]) -> dict[str, Any]:
    try:
        return JSDataParser(
            PORTFOLIO_DATA.read_text(encoding="utf-8")
        ).parse_assignment()
    except (OSError, JSDataParseError) as exc:
        errors.append(f"{display_path(PORTFOLIO_DATA)}: {exc}")
        return {}


def load_snapshot(errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{display_path(SNAPSHOT)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{display_path(SNAPSHOT)}: root value must be an object")
        return {}
    return value


def require_mapping(
    value: Any,
    label: str,
    errors: list[str],
) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    errors.append(f"{label}: expected object")
    return {}


def require_list(value: Any, label: str, errors: list[str]) -> list[Any]:
    if isinstance(value, list):
        return value
    errors.append(f"{label}: expected array")
    return []


def index_unique(
    values: list[Any],
    field: str,
    label: str,
    errors: list[str],
) -> dict[Any, dict[str, Any]]:
    indexed: dict[Any, dict[str, Any]] = {}
    for position, value in enumerate(values):
        if not isinstance(value, dict):
            errors.append(f"{label}[{position}]: expected object")
            continue
        key = value.get(field)
        if key is None:
            errors.append(f"{label}[{position}]: missing {field!r}")
            continue
        if key in indexed:
            errors.append(f"{label}: duplicate {field} {key!r}")
            continue
        indexed[key] = value
    return indexed


def compare(
    actual: Any,
    expected: Any,
    label: str,
    errors: list[str],
) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, found {actual!r}")


def compare_key_sets(
    actual: set[Any],
    expected: set[Any],
    label: str,
    errors: list[str],
) -> None:
    missing = sorted(expected - actual, key=str)
    extra = sorted(actual - expected, key=str)
    if missing:
        errors.append(f"{label}: missing {missing!r}")
    if extra:
        errors.append(f"{label}: unexpected {extra!r}")


def validate_detection_sources(
    detections: dict[str, Detection],
    searches: dict[str, dict[str, str]],
    portfolio: dict[str, Any],
    snapshot: dict[str, Any],
    errors: list[str],
) -> tuple[Counter[str], int]:
    compare(
        len(detections),
        EXPECTED_DETECTION_COUNT,
        "detections/*.md count",
        errors,
    )

    search_stanzas = {
        name: values for name, values in searches.items() if name.startswith("detect_")
    }
    compare(
        len(search_stanzas),
        EXPECTED_DETECTION_COUNT,
        "savedsearches.conf detection stanza count",
        errors,
    )

    site_detection_values = require_list(
        portfolio.get("detections"),
        "LAB_DATA.detections",
        errors,
    )
    site_detections = index_unique(
        site_detection_values,
        "id",
        "LAB_DATA.detections",
        errors,
    )
    compare(
        len(site_detections),
        EXPECTED_DETECTION_COUNT,
        "LAB_DATA.detections count",
        errors,
    )
    compare_key_sets(
        set(site_detections),
        set(detections),
        "LAB_DATA detection ids",
        errors,
    )

    expected_stanzas = {
        f"detect_{detection_id.replace('.', '_')}" for detection_id in detections
    }
    compare_key_sets(
        set(search_stanzas),
        expected_stanzas,
        "savedsearches.conf detection stanzas",
        errors,
    )

    statuses: Counter[str] = Counter()
    for detection_id, detection in sorted(detections.items()):
        metadata = detection.frontmatter
        status = metadata.get("status")
        if isinstance(status, str):
            statuses[status] += 1
        front_attack = metadata.get("attack")
        if not isinstance(front_attack, list) or not all(
            isinstance(item, dict) for item in front_attack
        ):
            errors.append(f"{display_path(detection.path)}: attack must be an array")
            front_attack = []
        techniques = [
            item.get("technique")
            for item in front_attack
            if isinstance(item.get("technique"), str)
        ]
        tactics = [
            item.get("tactic")
            for item in front_attack
            if isinstance(item.get("tactic"), str)
        ]
        schedule = require_mapping(
            metadata.get("schedule"),
            f"{display_path(detection.path)} schedule",
            errors,
        )

        stanza_name = f"detect_{detection_id.replace('.', '_')}"
        stanza = search_stanzas.get(stanza_name)
        if stanza is not None:
            compare(
                stanza.get("disabled"),
                "0",
                f"[{stanza_name}] disabled",
                errors,
            )
            compare(
                stanza.get("cron_schedule"),
                schedule.get("cron"),
                f"[{stanza_name}] cron_schedule",
                errors,
            )
            compare(
                stanza.get("dispatch.earliest_time"),
                schedule.get("earliest"),
                f"[{stanza_name}] dispatch.earliest_time",
                errors,
            )
            compare(
                stanza.get("dispatch.latest_time"),
                schedule.get("latest"),
                f"[{stanza_name}] dispatch.latest_time",
                errors,
            )
            compare(
                stanza.get("action.summary_index.detection_id"),
                detection_id,
                f"[{stanza_name}] detection_id",
                errors,
            )
            compare(
                stanza.get("action.summary_index.severity"),
                metadata.get("severity"),
                f"[{stanza_name}] severity",
                errors,
            )
            compare(
                stanza.get("action.summary_index.risk_score"),
                str(metadata.get("risk_score")),
                f"[{stanza_name}] risk_score",
                errors,
            )
            expected_primary_technique = techniques[0] if techniques else None
            compare(
                stanza.get("action.summary_index.attack_technique"),
                expected_primary_technique,
                f"[{stanza_name}] primary ATT&CK technique",
                errors,
            )
            if normalize_spl(stanza.get("search", "")) != normalize_spl(
                detection.spl
            ):
                errors.append(
                    f"{detection_id}: Markdown SPL differs from [{stanza_name}] search"
                )

        site_detection = site_detections.get(detection_id)
        if site_detection is None:
            continue
        compare(
            site_detection.get("file"),
            detection.path.name,
            f"LAB_DATA detection {detection_id} file",
            errors,
        )
        compare(
            site_detection.get("status"),
            status,
            f"LAB_DATA detection {detection_id} status",
            errors,
        )
        compare(
            site_detection.get("risk"),
            metadata.get("risk_score"),
            f"LAB_DATA detection {detection_id} risk",
            errors,
        )
        compare(
            site_detection.get("severity"),
            metadata.get("severity"),
            f"LAB_DATA detection {detection_id} severity",
            errors,
        )
        expected_primary_tactic = tactics[0] if tactics else None
        site_tactic = site_detection.get("tactic")
        normalized_site_tactic = TACTIC_ALIASES.get(site_tactic, site_tactic)
        compare(
            normalized_site_tactic,
            expected_primary_tactic,
            f"LAB_DATA detection {detection_id} primary tactic",
            errors,
        )
        site_techniques = site_detection.get("techniques")
        if not isinstance(site_techniques, list):
            errors.append(
                f"LAB_DATA detection {detection_id} techniques: expected array"
            )
        else:
            compare(
                set(site_techniques),
                set(techniques),
                f"LAB_DATA detection {detection_id} ATT&CK techniques",
                errors,
            )
            if len(site_techniques) != len(set(site_techniques)):
                errors.append(
                    f"LAB_DATA detection {detection_id} ATT&CK techniques: "
                    "duplicate value"
                )
        site_schedule = require_mapping(
            site_detection.get("schedule"),
            f"LAB_DATA detection {detection_id} schedule",
            errors,
        )
        for field in ("cron", "earliest", "latest"):
            compare(
                site_schedule.get(field),
                schedule.get(field),
                f"LAB_DATA detection {detection_id} schedule.{field}",
                errors,
            )
        site_spl = site_detection.get("spl")
        if not isinstance(site_spl, str):
            errors.append(f"LAB_DATA detection {detection_id} spl: expected string")
        else:
            if stanza is not None and normalize_spl(site_spl) != normalize_spl(
                stanza.get("search", "")
            ):
                errors.append(
                    f"LAB_DATA detection {detection_id} SPL differs from "
                    f"[{stanza_name}] search"
                )

    metrics = require_mapping(snapshot.get("metrics"), "snapshot.metrics", errors)
    compare(
        metrics.get("configured_detection_searches"),
        len(detections),
        "snapshot.metrics.configured_detection_searches",
        errors,
    )
    return statuses, len(site_detections)


def validate_cases(
    detections: dict[str, Detection],
    searches: dict[str, dict[str, str]],
    portfolio: dict[str, Any],
    errors: list[str],
) -> int:
    site_detections = index_unique(
        require_list(portfolio.get("detections"), "LAB_DATA.detections", errors),
        "id",
        "LAB_DATA.detections",
        errors,
    )
    cases = require_list(portfolio.get("cases"), "LAB_DATA.cases", errors)
    indexed_cases = index_unique(cases, "key", "LAB_DATA.cases", errors)
    seen_detection_ids: set[str] = set()
    for case_key, case in indexed_cases.items():
        detection_id = case.get("detectionId")
        if not isinstance(detection_id, str):
            errors.append(f"LAB_DATA case {case_key!r}: missing detectionId")
            continue
        if detection_id in seen_detection_ids:
            errors.append(
                f"LAB_DATA cases: detectionId {detection_id!r} is used more than once"
            )
        seen_detection_ids.add(detection_id)
        detection = detections.get(detection_id)
        site_detection = site_detections.get(detection_id)
        if detection is None:
            errors.append(
                f"LAB_DATA case {case_key!r}: unknown detectionId {detection_id!r}"
            )
            continue
        if site_detection is None:
            errors.append(
                f"LAB_DATA case {case_key!r}: detection absent from LAB_DATA.detections"
            )
            continue
        if detection.frontmatter.get("status") != "production":
            errors.append(
                f"LAB_DATA case {case_key!r}: showcased detection {detection_id} "
                "is not Production"
            )
        stanza_name = f"detect_{detection_id.replace('.', '_')}"
        stanza = searches.get(stanza_name, {})
        displayed_spl = site_detection.get("spl")
        if not isinstance(displayed_spl, str) or normalize_spl(
            displayed_spl
        ) != normalize_spl(stanza.get("search", "")):
            errors.append(
                f"LAB_DATA case {case_key!r}: displayed SPL is not the canonical "
                f"[{stanza_name}] search"
            )
        explicit_case_spl = case.get("spl")
        if explicit_case_spl is not None and (
            not isinstance(explicit_case_spl, str)
            or normalize_spl(explicit_case_spl)
            != normalize_spl(stanza.get("search", ""))
        ):
            errors.append(
                f"LAB_DATA case {case_key!r}: explicit case SPL differs from "
                f"[{stanza_name}] search"
            )
        evidence = case.get("evidence")
        if not isinstance(evidence, str) or not (ROOT / "site" / evidence).is_file():
            errors.append(
                f"LAB_DATA case {case_key!r}: missing evidence asset {evidence!r}"
            )
        validation = site_detection.get("validation")
        if isinstance(validation, dict) and validation.get("evidence") is not None:
            compare(
                evidence,
                validation.get("evidence"),
                f"LAB_DATA case {case_key!r} evidence",
                errors,
            )
    return len(indexed_cases)


def validate_snapshot(
    detections: dict[str, Detection],
    index_stanzas: dict[str, dict[str, str]],
    portfolio: dict[str, Any],
    snapshot: dict[str, Any],
    errors: list[str],
) -> tuple[int | None, int]:
    metrics = require_mapping(snapshot.get("metrics"), "snapshot.metrics", errors)
    platform = require_mapping(snapshot.get("platform"), "snapshot.platform", errors)
    meta = require_mapping(portfolio.get("meta"), "LAB_DATA.meta", errors)
    provenance = require_mapping(
        portfolio.get("provenance"),
        "LAB_DATA.provenance",
        errors,
    )
    snapshot_provenance = require_mapping(
        provenance.get("snapshot"),
        "LAB_DATA.provenance.snapshot",
        errors,
    )
    lifetime_provenance = require_mapping(
        provenance.get("lifetime"),
        "LAB_DATA.provenance.lifetime",
        errors,
    )

    compare(
        meta.get("splunkVersion"),
        platform.get("version"),
        "LAB_DATA.meta.splunkVersion",
        errors,
    )
    captured_at = snapshot.get("captured_at")
    captured_date = captured_at[:10] if isinstance(captured_at, str) else None
    compare(
        snapshot_provenance.get("capturedAt"),
        captured_date,
        "LAB_DATA.provenance.snapshot.capturedAt",
        errors,
    )
    compare(
        lifetime_provenance.get("capturedAt"),
        captured_date,
        "LAB_DATA.provenance.lifetime.capturedAt",
        errors,
    )
    compare(
        snapshot_provenance.get("totalEvents"),
        metrics.get("searchable_event_count"),
        "LAB_DATA.provenance.snapshot.totalEvents",
        errors,
    )
    compare(
        lifetime_provenance.get("totalEvents"),
        metrics.get("lifetime_event_count"),
        "LAB_DATA.provenance.lifetime.totalEvents",
        errors,
    )
    compare(
        metrics.get("configured_detection_searches"),
        len(detections),
        "snapshot configured detection count",
        errors,
    )

    snapshot_source_values = require_list(
        snapshot.get("searchable_sources"),
        "snapshot.searchable_sources",
        errors,
    )
    site_source_values = require_list(
        portfolio.get("sources"),
        "LAB_DATA.sources",
        errors,
    )

    def source_key(value: dict[str, Any]) -> tuple[Any, Any]:
        return value.get("index"), value.get("sourcetype")

    snapshot_sources: dict[tuple[Any, Any], dict[str, Any]] = {}
    for position, source in enumerate(snapshot_source_values):
        if not isinstance(source, dict):
            errors.append(f"snapshot.searchable_sources[{position}]: expected object")
            continue
        key = source_key(source)
        if key in snapshot_sources:
            errors.append(f"snapshot.searchable_sources: duplicate source {key!r}")
        snapshot_sources[key] = source
    site_sources: dict[tuple[Any, Any], dict[str, Any]] = {}
    for position, source in enumerate(site_source_values):
        if not isinstance(source, dict):
            errors.append(f"LAB_DATA.sources[{position}]: expected object")
            continue
        key = source_key(source)
        if key in site_sources:
            errors.append(f"LAB_DATA.sources: duplicate source {key!r}")
        site_sources[key] = source
    compare_key_sets(
        set(site_sources),
        set(snapshot_sources),
        "LAB_DATA source keys",
        errors,
    )
    for key, source in sorted(snapshot_sources.items(), key=lambda item: str(item[0])):
        if key in site_sources:
            compare(
                site_sources[key].get("count"),
                source.get("count"),
                f"LAB_DATA source {key!r} count",
                errors,
            )

    searchable_total = sum(
        source.get("count", 0)
        for source in snapshot_sources.values()
        if isinstance(source.get("count"), int)
    )
    compare(
        searchable_total,
        metrics.get("searchable_event_count"),
        "snapshot searchable source total",
        errors,
    )
    site_source_total = sum(
        source.get("count", 0)
        for source in site_sources.values()
        if isinstance(source.get("count"), int)
    )
    compare(
        site_source_total,
        metrics.get("searchable_event_count"),
        "LAB_DATA source total",
        errors,
    )
    sysmon_total = sum(
        source.get("count", 0)
        for key, source in snapshot_sources.items()
        if key[0] == "sysmon" and isinstance(source.get("count"), int)
    )
    windows_total = sum(
        source.get("count", 0)
        for key, source in snapshot_sources.items()
        if key[0] == "windows" and isinstance(source.get("count"), int)
    )
    compare(
        snapshot_provenance.get("sysmonEvents"),
        sysmon_total,
        "LAB_DATA.provenance.snapshot.sysmonEvents",
        errors,
    )
    compare(
        snapshot_provenance.get("windowsEvents"),
        windows_total,
        "LAB_DATA.provenance.snapshot.windowsEvents",
        errors,
    )

    snapshot_event_codes = index_unique(
        require_list(
            snapshot.get("sysmon_event_codes"),
            "snapshot.sysmon_event_codes",
            errors,
        ),
        "event_id",
        "snapshot.sysmon_event_codes",
        errors,
    )
    site_event_codes = index_unique(
        require_list(
            portfolio.get("eventCodes"),
            "LAB_DATA.eventCodes",
            errors,
        ),
        "code",
        "LAB_DATA.eventCodes",
        errors,
    )
    normalized_site_event_codes: dict[int, dict[str, Any]] = {}
    for key, value in site_event_codes.items():
        try:
            normalized_key = int(key)
        except (TypeError, ValueError):
            errors.append(f"LAB_DATA.eventCodes: invalid EventCode {key!r}")
            continue
        normalized_site_event_codes[normalized_key] = value
    compare_key_sets(
        set(normalized_site_event_codes),
        set(snapshot_event_codes),
        "LAB_DATA EventCode keys",
        errors,
    )
    for event_id, event in sorted(snapshot_event_codes.items()):
        if event_id in normalized_site_event_codes:
            compare(
                normalized_site_event_codes[event_id].get("count"),
                event.get("count"),
                f"LAB_DATA EventCode {event_id} count",
                errors,
            )
    event_code_total = sum(
        event.get("count", 0)
        for event in snapshot_event_codes.values()
        if isinstance(event.get("count"), int)
    )
    compare(
        event_code_total,
        sysmon_total,
        "snapshot Sysmon EventCode total",
        errors,
    )

    snapshot_indexes = index_unique(
        require_list(snapshot.get("indexes"), "snapshot.indexes", errors),
        "name",
        "snapshot.indexes",
        errors,
    )
    site_indexes = index_unique(
        require_list(portfolio.get("indexes"), "LAB_DATA.indexes", errors),
        "name",
        "LAB_DATA.indexes",
        errors,
    )
    compare_key_sets(
        set(site_indexes),
        set(snapshot_indexes),
        "LAB_DATA index names",
        errors,
    )
    configured_index_stanzas = {
        name: stanza for name, stanza in index_stanzas.items() if name != "default"
    }
    compare_key_sets(
        set(configured_index_stanzas),
        set(snapshot_indexes),
        "indexes.conf index names",
        errors,
    )
    compare(
        metrics.get("configured_indexes"),
        len(snapshot_indexes),
        "snapshot.metrics.configured_indexes",
        errors,
    )
    for name, snapshot_index in sorted(snapshot_indexes.items()):
        site_index = site_indexes.get(name)
        if site_index is not None:
            field_map = {
                "lifetime": "lifetime_events",
                "snapshot": "searchable_events",
                "maxMb": "max_size_mb",
                "retentionDays": "retention_days",
            }
            for site_field, snapshot_field in field_map.items():
                compare(
                    site_index.get(site_field),
                    snapshot_index.get(snapshot_field),
                    f"LAB_DATA index {name} {site_field}",
                    errors,
                )
        conf_index = configured_index_stanzas.get(name)
        if conf_index is not None:
            max_size = conf_index.get("maxTotalDataSizeMB")
            try:
                parsed_max_size = int(max_size) if max_size is not None else None
            except ValueError:
                parsed_max_size = None
            compare(
                parsed_max_size,
                snapshot_index.get("max_size_mb"),
                f"indexes.conf [{name}] maxTotalDataSizeMB",
                errors,
            )
            retention = conf_index.get("frozenTimePeriodInSecs")
            try:
                retention_days = (
                    int(retention) // 86400 if retention is not None else None
                )
            except ValueError:
                retention_days = None
            compare(
                retention_days,
                snapshot_index.get("retention_days"),
                f"indexes.conf [{name}] retention days",
                errors,
            )

    lifetime_total = sum(
        value.get("lifetime_events", 0)
        for value in snapshot_indexes.values()
        if isinstance(value.get("lifetime_events"), int)
    )
    index_searchable_total = sum(
        value.get("searchable_events", 0)
        for value in snapshot_indexes.values()
        if isinstance(value.get("searchable_events"), int)
    )
    compare(
        lifetime_total,
        metrics.get("lifetime_event_count"),
        "snapshot index lifetime total",
        errors,
    )
    compare(
        index_searchable_total,
        metrics.get("searchable_event_count"),
        "snapshot index searchable total",
        errors,
    )

    evidence_values = require_list(
        snapshot.get("evidence"),
        "snapshot.evidence",
        errors,
    )
    for position, evidence in enumerate(evidence_values):
        if not isinstance(evidence, dict):
            errors.append(f"snapshot.evidence[{position}]: expected object")
            continue
        relative_path = evidence.get("path")
        expected_sha256 = evidence.get("sha256")
        if not isinstance(relative_path, str):
            errors.append(f"snapshot.evidence[{position}]: missing path")
            continue
        evidence_path = (ROOT / relative_path).resolve()
        try:
            evidence_path.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(
                f"snapshot.evidence[{position}]: path escapes repository root"
            )
            continue
        if not evidence_path.is_file():
            errors.append(
                f"snapshot.evidence[{position}]: missing file {relative_path!r}"
            )
            continue
        actual_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        compare(
            actual_sha256,
            expected_sha256,
            f"snapshot evidence {relative_path} sha256",
            errors,
        )
    return metrics.get("searchable_event_count"), len(snapshot_indexes)


def main() -> int:
    errors: list[str] = []
    detections = load_detections(errors)
    searches = parse_conf(SAVED_SEARCHES, errors)
    index_stanzas = parse_conf(INDEXES_CONF, errors)
    portfolio = load_portfolio_data(errors)
    snapshot = load_snapshot(errors)

    statuses, site_detection_count = validate_detection_sources(
        detections,
        searches,
        portfolio,
        snapshot,
        errors,
    )
    case_count = validate_cases(detections, searches, portfolio, errors)
    searchable_events, index_count = validate_snapshot(
        detections,
        index_stanzas,
        portfolio,
        snapshot,
        errors,
    )

    summary = (
        f"{len(detections)} detections "
        f"({statuses.get('production', 0)} Production / "
        f"{statuses.get('testing', 0)} Testing), "
        f"{site_detection_count} portfolio entries, "
        f"{case_count} investigation cases, "
        f"{searchable_events!r} searchable events, "
        f"{index_count} indexes"
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAILED: portfolio consistency audit ({summary})", file=sys.stderr)
        return 1
    print(f"OK: portfolio consistency validated ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
