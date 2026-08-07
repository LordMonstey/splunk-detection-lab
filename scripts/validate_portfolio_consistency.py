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
SNAPSHOT = ROOT / "artifacts" / "public" / "splunk-engineering-snapshot-20260806.json"
EVIDENCE_REDACTION_REGISTER = (
    ROOT / "artifacts" / "public" / "evidence-redaction-register-20260807.json"
)
EXPECTED_PUBLIC_SURFACES = {
    "command-center": "assets/evidence/engineering-command-center.png",
    "detection-factory": "assets/evidence/detection-factory-control-plane.png",
    "risk-investigation": "assets/evidence/risk-correlation-assurance.png",
}
EXPECTED_CASE_SURFACES = {
    "lsass": "assets/evidence/risk-correlation-assurance.png",
    "regsvr32": "assets/evidence/detection-factory-control-plane.png",
    "powershell": "assets/evidence/engineering-command-center.png",
}
ADMIN_EVIDENCE_ARTIFACTS = {
    "custom-datamodel": "artifacts/public/custom-datamodel-live-evidence-10.2.1-20260807.json",
    "upgrade-rollback": "artifacts/public/upgrade-evidence-9-4-13-to-10-2-1-live.json",
    "tls-lifecycle": "artifacts/public/tls-rotation-evidence-20260807.json",
    "rbac-governance": "artifacts/public/rbac-live-evidence-9.4.13-20260807.json",
    "mco-readonly": "artifacts/public/mco-live-read-only-qualification-20260807.json",
    "periodic-reporting": "artifacts/public/periodic-reporting-live-evidence-10.2.1-20260807.json",
    "parsing-rollback": "artifacts/public/parsing-canary-rollback-evidence-20260807.json",
    "cluster-resilience": "artifacts/public/cluster-resilience-evidence-20260806.json",
    "linux-onboarding": "artifacts/public/linux-onboarding-evidence-20260807.json",
}

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
        compare(
            evidence,
            EXPECTED_CASE_SURFACES.get(case_key),
            f"LAB_DATA case {case_key!r} aggregate surface",
            errors,
        )
        evidence_alt = require_mapping(
            case.get("evidenceAlt"),
            f"LAB_DATA case {case_key!r} evidenceAlt",
            errors,
        )
        if "agrégée" not in str(evidence_alt.get("fr", "")).lower():
            errors.append(
                f"LAB_DATA case {case_key!r}: French caption must identify an "
                "aggregate surface"
            )
        if "aggregate" not in str(evidence_alt.get("en", "")).lower():
            errors.append(
                f"LAB_DATA case {case_key!r}: English caption must identify an "
                "aggregate surface"
            )
        validation = site_detection.get("validation")
        if isinstance(validation, dict) and validation.get("evidence") is not None:
            errors.append(
                f"LAB_DATA case {case_key!r}: detection validation must not link "
                "a public case-level image"
            )
    return len(indexed_cases)


def validate_evidence_gallery(
    portfolio: dict[str, Any],
    errors: list[str],
) -> int:
    values = require_list(portfolio.get("evidence"), "LAB_DATA.evidence", errors)
    gallery = index_unique(values, "id", "LAB_DATA.evidence", errors)
    compare_key_sets(
        set(gallery),
        set(EXPECTED_PUBLIC_SURFACES),
        "LAB_DATA public surface ids",
        errors,
    )
    for surface_id, expected_image in EXPECTED_PUBLIC_SURFACES.items():
        entry = gallery.get(surface_id)
        if entry is None:
            continue
        compare(
            entry.get("image"),
            expected_image,
            f"LAB_DATA public surface {surface_id} image",
            errors,
        )
        image_path = ROOT / "site" / expected_image
        if not image_path.is_file():
            errors.append(
                f"LAB_DATA public surface {surface_id}: missing image "
                f"{expected_image!r}"
            )
        caption = require_mapping(
            entry.get("caption"),
            f"LAB_DATA public surface {surface_id} caption",
            errors,
        )
        if "agrégée" not in str(caption.get("fr", "")).lower():
            errors.append(
                f"LAB_DATA public surface {surface_id}: French caption must "
                "identify an aggregate capture"
            )
        if "aggregate" not in str(caption.get("en", "")).lower():
            errors.append(
                f"LAB_DATA public surface {surface_id}: English caption must "
                "identify an aggregate capture"
            )
        claim = entry.get("claim")
        if not isinstance(claim, str) or not claim:
            errors.append(
                f"LAB_DATA public surface {surface_id}: expected non-empty claim"
            )
        elif "tests/atomic/evidence" in claim or "screenshots/" in claim:
            errors.append(
                f"LAB_DATA public surface {surface_id}: raw evidence path is forbidden"
            )
    return len(gallery)


def load_public_evidence(relative_path: str, errors: list[str]) -> dict[str, Any]:
    path = (ROOT / relative_path).resolve()
    public_root = (ROOT / "artifacts" / "public").resolve()
    try:
        path.relative_to(public_root)
    except ValueError:
        errors.append(f"public evidence path escapes artifacts/public: {relative_path!r}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{relative_path}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{relative_path}: root value must be an object")
        return {}
    return value


def load_withdrawn_evidence_paths(errors: list[str]) -> set[str]:
    try:
        register = json.loads(EVIDENCE_REDACTION_REGISTER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{display_path(EVIDENCE_REDACTION_REGISTER)}: {exc}")
        return set()
    if not isinstance(register, dict):
        errors.append("evidence redaction register: root value must be an object")
        return set()
    entries = require_list(
        register.get("withdrawn_assets"),
        "evidence redaction register withdrawn_assets",
        errors,
    )
    withdrawn: set[str] = set()
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(
                f"evidence redaction register withdrawn_assets[{position}]: "
                "expected object"
            )
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            errors.append(
                f"evidence redaction register withdrawn_assets[{position}]: "
                "missing path"
            )
            continue
        if entry.get("status") != "withdrawn":
            errors.append(
                f"evidence redaction register {path!r}: expected status='withdrawn'"
            )
            continue
        if path in withdrawn:
            errors.append(f"evidence redaction register: duplicate path {path!r}")
            continue
        withdrawn.add(path)
    return withdrawn


def validate_admin_evidence(
    portfolio: dict[str, Any],
    errors: list[str],
) -> int:
    values = require_list(
        portfolio.get("adminEvidence"),
        "LAB_DATA.adminEvidence",
        errors,
    )
    proofs = index_unique(values, "id", "LAB_DATA.adminEvidence", errors)
    compare_key_sets(
        set(proofs),
        set(ADMIN_EVIDENCE_ARTIFACTS),
        "LAB_DATA administration evidence ids",
        errors,
    )

    artifacts: dict[str, dict[str, Any]] = {}
    for proof_id, expected_path in ADMIN_EVIDENCE_ARTIFACTS.items():
        proof = proofs.get(proof_id)
        if proof is None:
            continue
        compare(
            proof.get("artifact"),
            expected_path,
            f"LAB_DATA admin evidence {proof_id} artifact",
            errors,
        )
        for field in ("category", "title", "metricLabel", "detail"):
            localized = require_mapping(
                proof.get(field),
                f"LAB_DATA admin evidence {proof_id} {field}",
                errors,
            )
            for language in ("fr", "en"):
                if not isinstance(localized.get(language), str) or not localized.get(language):
                    errors.append(
                        f"LAB_DATA admin evidence {proof_id} {field}.{language}: "
                        "expected non-empty string"
                    )
        artifacts[proof_id] = load_public_evidence(expected_path, errors)

    upgrade = artifacts.get("upgrade-rollback", {})
    phases = require_mapping(upgrade.get("phases"), "upgrade evidence phases", errors)
    expected_versions = {
        "pre_upgrade": "9.4.13",
        "post_upgrade": "10.2.1",
        "rollback": "9.4.13",
        "final": "10.2.1",
    }
    passed_smoke_tests = 0
    total_smoke_tests = 0
    for phase_name, expected_version in expected_versions.items():
        phase = require_mapping(
            phases.get(phase_name),
            f"upgrade evidence phase {phase_name}",
            errors,
        )
        compare(
            phase.get("version"),
            expected_version,
            f"upgrade evidence phase {phase_name} version",
            errors,
        )
        smoke_tests = require_list(
            phase.get("smoke_tests"),
            f"upgrade evidence phase {phase_name} smoke tests",
            errors,
        )
        total_smoke_tests += len(smoke_tests)
        passed_smoke_tests += sum(
            1
            for test in smoke_tests
            if isinstance(test, dict) and test.get("status") == "passed"
        )
    compare(total_smoke_tests, 32, "upgrade evidence smoke test count", errors)
    compare(passed_smoke_tests, 32, "upgrade evidence passed smoke tests", errors)
    upgrade_decisions = require_mapping(
        upgrade.get("decisions"), "upgrade evidence decisions", errors
    )
    final_decision = require_mapping(
        upgrade_decisions.get("final"), "upgrade evidence final decision", errors
    )
    compare(final_decision.get("decision"), "CLOSE", "upgrade final decision", errors)
    if "upgrade-rollback" in proofs:
        compare(
            proofs["upgrade-rollback"].get("metric"),
            "32/32",
            "LAB_DATA upgrade metric",
            errors,
        )

    tls = artifacts.get("tls-lifecycle", {})
    tls_controls = require_mapping(tls.get("live_controls"), "TLS live controls", errors)
    compare(tls.get("status"), "passed_after_remediation", "TLS evidence status", errors)
    compare(len(tls_controls), 12, "TLS live control count", errors)
    compare(
        sum(value is True for value in tls_controls.values()),
        12,
        "TLS passed live controls",
        errors,
    )
    if "tls-lifecycle" in proofs:
        compare(proofs["tls-lifecycle"].get("metric"), "12/12", "LAB_DATA TLS metric", errors)

    rbac = artifacts.get("rbac-governance", {})
    rbac_summary = require_mapping(rbac.get("summary"), "RBAC summary", errors)
    compare(rbac.get("status"), "passed", "RBAC evidence status", errors)
    compare(rbac_summary.get("total"), 38, "RBAC test count", errors)
    compare(rbac_summary.get("passed"), 38, "RBAC passed tests", errors)
    rbac_cleanup = require_mapping(rbac.get("cleanup"), "RBAC cleanup", errors)
    compare(rbac_cleanup.get("ephemeral_users_created"), 6, "RBAC temporary users created", errors)
    compare(rbac_cleanup.get("ephemeral_users_removed"), 6, "RBAC temporary users removed", errors)
    if "rbac-governance" in proofs:
        compare(proofs["rbac-governance"].get("metric"), "38/38", "LAB_DATA RBAC metric", errors)

    mco = artifacts.get("mco-readonly", {})
    mco_controls = require_mapping(mco.get("controls"), "MCO controls", errors)
    compare(mco.get("status"), "PASS", "MCO evidence status", errors)
    compare(len(mco_controls), 5, "MCO control domain count", errors)
    compare(
        sum(
            isinstance(control, dict) and control.get("status") == "PASS"
            for control in mco_controls.values()
        ),
        5,
        "MCO passed control domains",
        errors,
    )
    if "mco-readonly" in proofs:
        compare(proofs["mco-readonly"].get("metric"), "5/5", "LAB_DATA MCO metric", errors)

    reporting = artifacts.get("periodic-reporting", {})
    compare(reporting.get("status"), "PASS", "periodic reporting status", errors)
    reporting_checks = require_mapping(
        reporting.get("checks"), "periodic reporting checks", errors
    )
    compare(len(reporting_checks), 16, "periodic reporting check count", errors)
    compare(
        sum(value is True for value in reporting_checks.values()),
        16,
        "periodic reporting passed checks",
        errors,
    )
    reporting_runtime = require_mapping(
        reporting.get("runtime_contract"),
        "periodic reporting runtime contract",
        errors,
    )
    reporting_collectors = require_list(
        reporting_runtime.get("collectors"),
        "periodic reporting collectors",
        errors,
    )
    compare(len(reporting_collectors), 2, "periodic reporting collector count", errors)
    compare(
        sum(
            isinstance(collector, dict)
            and collector.get("scheduled") is True
            and collector.get("schedule_match") is True
            and collector.get("search_contract_match") is True
            for collector in reporting_collectors
        ),
        2,
        "periodic reporting scheduled collector contracts",
        errors,
    )
    reporting_dashboard = require_mapping(
        reporting_runtime.get("dashboard"),
        "periodic reporting dashboard",
        errors,
    )
    compare(reporting_dashboard.get("query_count"), 10, "periodic reporting dashboard query count", errors)
    compare(reporting_dashboard.get("aggregate_only"), True, "periodic reporting aggregate-only dashboard", errors)
    reporting_execution = require_mapping(
        reporting.get("aggregate_execution"),
        "periodic reporting aggregate execution",
        errors,
    )
    first_cycle = require_mapping(
        reporting_execution.get("after_first_cycle"),
        "periodic reporting first cycle",
        errors,
    )
    replay_cycle = require_mapping(
        reporting_execution.get("after_idempotence_replay"),
        "periodic reporting replay cycle",
        errors,
    )
    for label, cycle in (("first cycle", first_cycle), ("replay cycle", replay_cycle)):
        compare(cycle.get("row_count"), 16, f"periodic reporting {label} row count", errors)
        compare(cycle.get("valid_rows"), 16, f"periodic reporting {label} valid rows", errors)
        compare(cycle.get("duplicate_keys"), 0, f"periodic reporting {label} duplicate keys", errors)
        compare(cycle.get("family_count"), 2, f"periodic reporting {label} family count", errors)
        compare(cycle.get("mco_daily_periods"), 1, f"periodic reporting {label} daily periods", errors)
        compare(cycle.get("cim_weekly_periods"), 1, f"periodic reporting {label} weekly periods", errors)
    compare(
        reporting_execution.get("keyed_replay_stable"),
        True,
        "periodic reporting idempotent replay",
        errors,
    )
    reporting_periods = require_mapping(
        reporting.get("historical_periods_observed"),
        "periodic reporting observed periods",
        errors,
    )
    compare(reporting_periods.get("mco_daily"), 1, "periodic reporting daily period limit", errors)
    compare(reporting_periods.get("cim_weekly"), 1, "periodic reporting weekly period limit", errors)
    compare(reporting.get("trend_eligible"), False, "periodic reporting trend eligibility", errors)
    compare(reporting.get("trend_claimed"), False, "periodic reporting trend claim", errors)
    if "periodic-reporting" in proofs:
        reporting_proof = proofs["periodic-reporting"]
        compare(reporting_proof.get("metric"), "16/16", "LAB_DATA periodic reporting metric", errors)
        reporting_reference = require_mapping(
            reporting_proof.get("reference"),
            "LAB_DATA periodic reporting reference",
            errors,
        )
        compare(
            reporting_reference.get("fr"),
            "2 schedules · 16 lignes · 0 doublon · 10 requêtes agrégées",
            "LAB_DATA periodic reporting French reference",
            errors,
        )
        compare(
            reporting_reference.get("en"),
            "2 schedules · 16 rows · 0 duplicates · 10 aggregate queries",
            "LAB_DATA periodic reporting English reference",
            errors,
        )

    parsing = artifacts.get("parsing-rollback", {})
    compare(parsing.get("evidence_kind"), "live-isolated-lab", "parsing evidence kind", errors)
    parsing_change = require_mapping(parsing.get("change"), "parsing change", errors)
    compare(
        parsing_change.get("execution_mode"),
        "canary-recipe-only",
        "parsing execution boundary",
        errors,
    )
    compare(
        parsing_change.get("promotion_boundary"),
        "candidate-not-promotion-eligible",
        "parsing promotion boundary",
        errors,
    )
    parsing_decisions = require_mapping(parsing.get("decisions"), "parsing decisions", errors)
    expected_decisions = {
        "baseline": "GO-CANARY",
        "candidate": "NO-GO",
        "rollback": "CLOSE",
    }
    for phase_name, expected_decision in expected_decisions.items():
        decision = require_mapping(
            parsing_decisions.get(phase_name),
            f"parsing {phase_name} decision",
            errors,
        )
        compare(
            decision.get("decision"),
            expected_decision,
            f"parsing {phase_name} decision value",
            errors,
        )

    parsing_phases = require_mapping(parsing.get("phases"), "parsing phases", errors)
    expected_phase_contract = {
        "baseline": ("PASS", 100.0, 100.0),
        "candidate": ("NO-GO", 0.0, 0.0),
        "rollback": ("PASS", 100.0, 100.0),
    }
    for phase_name, (expected_gate, expected_coverage, expected_timestamp) in expected_phase_contract.items():
        phase = require_mapping(
            parsing_phases.get(phase_name),
            f"parsing {phase_name} phase",
            errors,
        )
        compare(phase.get("gate"), expected_gate, f"parsing {phase_name} gate", errors)
        compare(phase.get("expected_event_count"), 5, f"parsing {phase_name} expected events", errors)
        compare(phase.get("observed_event_count"), 5, f"parsing {phase_name} observed events", errors)
        compare(phase.get("distinct_event_count"), 5, f"parsing {phase_name} distinct events", errors)
        compare(phase.get("duplicate_count"), 0, f"parsing {phase_name} duplicates", errors)
        compare(phase.get("truncated_event_count"), 0, f"parsing {phase_name} truncation", errors)
        compare(
            phase.get("timestamp_conformance_pct"),
            expected_timestamp,
            f"parsing {phase_name} timestamp conformance",
            errors,
        )
        field_coverage = require_mapping(
            phase.get("required_field_coverage_pct"),
            f"parsing {phase_name} field coverage",
            errors,
        )
        compare_key_sets(
            set(field_coverage),
            {"action", "src", "user"},
            f"parsing {phase_name} field coverage keys",
            errors,
        )
        for field_name in ("action", "src", "user"):
            compare(
                field_coverage.get(field_name),
                expected_coverage,
                f"parsing {phase_name} {field_name} coverage",
                errors,
            )

    candidate_failed_checks = require_list(
        require_mapping(parsing_phases.get("candidate"), "parsing candidate phase", errors).get("failed_checks"),
        "parsing candidate failed checks",
        errors,
    )
    compare_key_sets(
        set(candidate_failed_checks),
        {"required_field_coverage", "timestamp_conformance"},
        "parsing candidate failed checks",
        errors,
    )
    parsing_packages = require_mapping(parsing.get("packages"), "parsing packages", errors)
    baseline_package = require_mapping(parsing_packages.get("baseline"), "parsing baseline package", errors)
    candidate_package = require_mapping(parsing_packages.get("candidate"), "parsing candidate package", errors)
    rollback_package = require_mapping(parsing_packages.get("rollback"), "parsing rollback package", errors)
    compare(baseline_package.get("version"), "1.0.0", "parsing baseline version", errors)
    compare(candidate_package.get("version"), "1.1.0-rc1", "parsing candidate version", errors)
    compare(rollback_package.get("version"), "1.0.0", "parsing rollback version", errors)
    for hash_field in ("archive_sha256", "effective_config_sha256"):
        compare(
            rollback_package.get(hash_field),
            baseline_package.get(hash_field),
            f"parsing rollback {hash_field} parity",
            errors,
        )
        if candidate_package.get(hash_field) == baseline_package.get(hash_field):
            errors.append(f"parsing candidate {hash_field}: expected a controlled difference")

    parsing_parity = require_mapping(parsing.get("rollback_parity"), "parsing rollback parity", errors)
    compare(parsing_parity.get("status"), "RESTORED", "parsing rollback parity status", errors)
    parity_checks = require_mapping(parsing_parity.get("checks"), "parsing rollback checks", errors)
    if not parity_checks or not all(value is True for value in parity_checks.values()):
        errors.append("parsing rollback checks: expected every check to pass")
    public_redaction = require_mapping(parsing.get("public_redaction"), "parsing public redaction", errors)
    if not public_redaction or not all(value is True for value in public_redaction.values()):
        errors.append("parsing public redaction: expected every boundary to pass")
    if "parsing-rollback" in proofs:
        parsing_proof = proofs["parsing-rollback"]
        compare(
            parsing_proof.get("metric"),
            "100 → 0 → 100",
            "LAB_DATA parsing rollback metric",
            errors,
        )
        parsing_reference = require_mapping(
            parsing_proof.get("reference"),
            "LAB_DATA parsing rollback reference",
            errors,
        )
        compare(
            parsing_reference.get("fr"),
            "baseline PASS · candidat NO-GO · rollback PASS",
            "LAB_DATA parsing rollback French reference",
            errors,
        )
        compare(
            parsing_reference.get("en"),
            "baseline PASS · candidate NO-GO · rollback PASS",
            "LAB_DATA parsing rollback English reference",
            errors,
        )

    cluster = artifacts.get("cluster-resilience", {})
    topology = require_mapping(cluster.get("topology"), "cluster topology", errors)
    compare(topology.get("replication_factor"), 2, "cluster RF", errors)
    compare(topology.get("search_factor"), 2, "cluster SF", errors)
    cluster_test = require_mapping(cluster.get("test"), "cluster test", errors)
    continuity = require_mapping(
        cluster_test.get("search_continuity"), "cluster search continuity", errors
    )
    compare(continuity.get("success"), True, "cluster search continuity", errors)
    recovered = require_mapping(
        cluster_test.get("recovered_health"), "cluster recovered health", errors
    )
    for field in (
        "all_peers_are_up",
        "replication_factor_met",
        "search_factor_met",
        "all_data_is_searchable",
        "no_fixup_tasks_in_progress",
    ):
        compare(recovered.get(field), True, f"cluster recovered health {field}", errors)
    if "cluster-resilience" in proofs:
        compare(
            proofs["cluster-resilience"].get("metric"),
            "RF2 / SF2",
            "LAB_DATA cluster metric",
            errors,
        )

    linux = artifacts.get("linux-onboarding", {})
    compare(linux.get("overall_pass"), True, "Linux onboarding status", errors)
    batch = require_mapping(linux.get("batch"), "Linux onboarding batch", errors)
    inventory = require_mapping(
        linux.get("inventory"), "Linux onboarding inventory", errors
    )
    observed = require_mapping(
        inventory.get("observed_by_sourcetype"),
        "Linux observed sourcetypes",
        errors,
    )
    compare(batch.get("expected_events"), 13, "Linux expected event count", errors)
    compare(sum(value for value in observed.values() if isinstance(value, int)), 13, "Linux observed event count", errors)
    cim_contract = require_mapping(
        linux.get("cim_field_contract"), "Linux CIM field contract", errors
    )
    compare(len(cim_contract), 4, "Linux CIM scope count", errors)
    compare(
        sum(
            isinstance(scope, dict) and scope.get("completeness_percent") == 100.0
            for scope in cim_contract.values()
        ),
        4,
        "Linux complete CIM scopes",
        errors,
    )
    linux_environment = require_mapping(
        linux.get("environment"), "Linux onboarding environment", errors
    )
    compare(
        linux_environment.get("application_version"),
        "0.7.2",
        "Linux onboarding historical app version",
        errors,
    )
    if "linux-onboarding" in proofs:
        compare(
            proofs["linux-onboarding"].get("metric"),
            "13/13",
            "LAB_DATA Linux onboarding metric",
            errors,
        )

    custom_dm = artifacts.get("custom-datamodel", {})
    compare(custom_dm.get("overall_pass"), True, "custom data model status", errors)
    dm_environment = require_mapping(
        custom_dm.get("environment"), "custom data model environment", errors
    )
    compare(dm_environment.get("splunk_version"), "10.2.1", "custom data model Splunk version", errors)
    compare(dm_environment.get("application_version"), "0.7.3", "custom data model app version", errors)
    compare(dm_environment.get("splunkd_health"), "green", "custom data model splunkd health", errors)
    compare(dm_environment.get("kv_store_status"), "ready", "custom data model KV Store status", errors)

    dm_classification = require_mapping(
        custom_dm.get("classification"), "custom data model classification", errors
    )
    compare(dm_classification.get("custom_data_model"), True, "custom data model boundary", errors)
    compare(dm_classification.get("native_cim_data_model"), False, "native CIM boundary", errors)
    compare(dm_classification.get("splunk_sa_cim_installed"), False, "Splunk_SA_CIM boundary", errors)
    compare(
        dm_classification.get("enterprise_security_app_installed"),
        False,
        "Enterprise Security boundary",
        errors,
    )

    dm_acceptance = require_mapping(
        custom_dm.get("acceptance"), "custom data model acceptance", errors
    )
    compare(len(dm_acceptance), 13, "custom data model acceptance count", errors)
    compare(
        sum(value is True for value in dm_acceptance.values()),
        13,
        "custom data model passed acceptance count",
        errors,
    )

    dm_acceleration = require_mapping(
        custom_dm.get("acceleration"), "custom data model acceleration", errors
    )
    dm_summary = require_mapping(
        dm_acceleration.get("summary"), "custom data model summary", errors
    )
    compare(dm_acceleration.get("enabled"), True, "custom data model acceleration enabled", errors)
    compare(dm_summary.get("complete"), True, "custom data model summary complete", errors)
    compare(dm_summary.get("bucket_count"), 4, "custom data model summary bucket count", errors)
    compare(dm_summary.get("last_error_present"), False, "custom data model summary error state", errors)

    dm_quality = require_mapping(
        custom_dm.get("data_quality"), "custom data model data quality", errors
    )
    compare(dm_quality.get("parity_percent"), 100.0, "custom data model parity", errors)
    compare(dm_quality.get("count_delta"), 0, "custom data model count delta", errors)
    compare(dm_quality.get("latest_delta_seconds"), 0.0, "custom data model latest delta", errors)
    compare(dm_quality.get("freshness_sla_seconds"), 900, "custom data model freshness SLA", errors)
    freshness_age = dm_quality.get("summary_freshness_age_seconds")
    if not isinstance(freshness_age, (int, float)) or isinstance(freshness_age, bool) or not 0 <= freshness_age < 900:
        errors.append("custom data model freshness: expected numeric value in [0, 900)")
    raw_count = dm_quality.get("raw_event_count")
    summary_count = dm_quality.get("summary_event_count")
    if not isinstance(raw_count, int) or raw_count <= 0 or raw_count != summary_count:
        errors.append("custom data model aggregate counts: expected equal non-zero integers")

    meta = require_mapping(portfolio.get("meta"), "LAB_DATA.meta", errors)
    compare(
        meta.get("appVersion"),
        dm_environment.get("application_version"),
        "LAB_DATA current app version",
        errors,
    )
    if "custom-datamodel" in proofs:
        custom_proof = proofs["custom-datamodel"]
        compare(custom_proof.get("metric"), "13/13", "LAB_DATA custom data model metric", errors)
        dm_reference = require_mapping(
            custom_proof.get("reference"), "LAB_DATA custom data model reference", errors
        )
        compare(
            dm_reference.get("fr"),
            "parité 100 % · 4 buckets · fraîcheur < 900 s",
            "LAB_DATA custom data model French reference",
            errors,
        )
        compare(
            dm_reference.get("en"),
            "100% parity · 4 buckets · freshness < 900 s",
            "LAB_DATA custom data model English reference",
            errors,
        )

    return len(proofs)


def validate_snapshot(
    detections: dict[str, Detection],
    index_stanzas: dict[str, dict[str, str]],
    portfolio: dict[str, Any],
    snapshot: dict[str, Any],
    withdrawn_evidence_paths: set[str],
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
    missing_snapshot_indexes = set(snapshot_indexes) - set(configured_index_stanzas)
    if missing_snapshot_indexes:
        errors.append(
            "indexes.conf index names: missing snapshot indexes "
            f"{sorted(missing_snapshot_indexes)}"
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
            if relative_path not in withdrawn_evidence_paths:
                errors.append(
                    f"snapshot.evidence[{position}]: missing file {relative_path!r} "
                    "without an exact withdrawn entry"
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
    withdrawn_evidence_paths = load_withdrawn_evidence_paths(errors)

    statuses, site_detection_count = validate_detection_sources(
        detections,
        searches,
        portfolio,
        snapshot,
        errors,
    )
    case_count = validate_cases(detections, searches, portfolio, errors)
    gallery_count = validate_evidence_gallery(portfolio, errors)
    admin_evidence_count = validate_admin_evidence(portfolio, errors)
    searchable_events, index_count = validate_snapshot(
        detections,
        index_stanzas,
        portfolio,
        snapshot,
        withdrawn_evidence_paths,
        errors,
    )

    summary = (
        f"{len(detections)} detections "
        f"({statuses.get('production', 0)} Production / "
        f"{statuses.get('testing', 0)} Testing), "
        f"{site_detection_count} portfolio entries, "
        f"{case_count} investigation cases, "
        f"{gallery_count} reviewed aggregate surfaces, "
        f"{admin_evidence_count} administration proofs, "
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
