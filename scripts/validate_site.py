#!/usr/bin/env python3
"""Security and integrity checks for the static portfolio."""

from __future__ import annotations

import re
import struct
import sys
import zlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
INDEX = SITE / "index.html"

FORBIDDEN_ELEMENTS = {"embed", "form", "iframe", "object"}
FORBIDDEN_JS = {
    "document.write": re.compile(r"\bdocument\s*\.\s*write\s*\(", re.I),
    "dynamic code evaluation": re.compile(
        r"\beval\s*\(|\bnew\s+Function\s*\(", re.I
    ),
    "HTML assignment": re.compile(
        r"\.(?:innerHTML|outerHTML)\s*=|\.insertAdjacentHTML\s*\(", re.I
    ),
}
PRIVATE_IP = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
SECRET_PATTERNS = {
    "Splunk CLI credential": re.compile(r"-auth\s+\S+:\S+", re.I),
    "credential assignment": re.compile(
        r"\b(?:password|passwd|secret|token)\s*[:=]\s*[\"']?[^<\s\"']{6,}",
        re.I,
    ),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
REQUIRED_CSP = {
    "default-src": "'self'",
    "base-uri": "'none'",
    "connect-src": "'none'",
    "form-action": "'none'",
    "frame-src": "'none'",
    "img-src": "'self'",
    "object-src": "'none'",
    "script-src": "'self'",
    "worker-src": "'none'",
}
FORBIDDEN_PNG_CHUNKS = {
    b"eXIf": "EXIF metadata",
    b"iTXt": "international text metadata",
    b"tEXt": "text metadata",
    b"tIME": "last-modification metadata",
    b"zTXt": "compressed text metadata",
}
PUBLIC_TEXT_ROOTS = (SITE, ROOT / "artifacts" / "public")
PUBLIC_PNG_ROOTS = (
    SITE,
    ROOT / "screenshots",
    ROOT / "tests" / "atomic" / "evidence",
    ROOT / "conf" / "splunk" / "appserver" / "static",
    ROOT / "conf" / "splunk" / "static",
)


def is_external(value: str) -> bool:
    return urlsplit(value).scheme.lower() in {"http", "https"}


def local_target(value: str) -> Path | None:
    parsed = urlsplit(value)
    if not value or value.startswith(("#", "data:")) or parsed.scheme:
        return None
    clean = unquote(parsed.path)
    if not clean:
        return None
    if clean.startswith("/"):
        clean = clean.lstrip("/")
    candidate = (SITE / clean).resolve()
    try:
        candidate.relative_to(SITE.resolve())
    except ValueError:
        raise ValueError(f"path escapes site root: {value}")
    return candidate


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.errors: list[str] = []
        self.ids: dict[str, int] = {}
        self.references: list[tuple[str, str, int]] = []
        self.csp: str | None = None
        self.referrer: str | None = None
        self.html_lang: str | None = None
        self.inline_script_line: int | None = None
        self.in_inline_script = False

    def handle_starttag(
        self, tag: str, attrs_list: list[tuple[str, str | None]]
    ) -> None:
        attrs = {key.lower(): value or "" for key, value in attrs_list}
        tag = tag.lower()

        if tag == "html":
            self.html_lang = attrs.get("lang")
        if tag in FORBIDDEN_ELEMENTS:
            self.errors.append(f"line {self.getpos()[0]}: forbidden <{tag}> element")

        for key in attrs:
            if key.startswith("on"):
                self.errors.append(
                    f"line {self.getpos()[0]}: inline event handler {key!r}"
                )

        element_id = attrs.get("id")
        if element_id:
            if element_id in self.ids:
                self.errors.append(
                    f"line {self.getpos()[0]}: duplicate id {element_id!r} "
                    f"(first seen line {self.ids[element_id]})"
                )
            self.ids[element_id] = self.getpos()[0]

        if tag == "a":
            href = attrs.get("href", "")
            if href:
                self.references.append(("href", href, self.getpos()[0]))
            if attrs.get("target", "").lower() == "_blank":
                rel = set(attrs.get("rel", "").lower().split())
                missing = {"noopener", "noreferrer"} - rel
                if missing:
                    self.errors.append(
                        f"line {self.getpos()[0]}: target=_blank misses "
                        + ", ".join(sorted(missing))
                    )
        elif tag == "img":
            src = attrs.get("src", "")
            if src:
                self.references.append(("src", src, self.getpos()[0]))
            if not attrs.get("alt"):
                self.errors.append(f"line {self.getpos()[0]}: image has no alt text")
        elif tag == "script":
            src = attrs.get("src")
            if src:
                self.references.append(("src", src, self.getpos()[0]))
                if is_external(src):
                    self.errors.append(
                        f"line {self.getpos()[0]}: external script is forbidden"
                    )
            else:
                self.in_inline_script = True
                self.inline_script_line = self.getpos()[0]
        elif tag == "link" and attrs.get("href"):
            self.references.append(("href", attrs["href"], self.getpos()[0]))
            if "stylesheet" in attrs.get("rel", "").lower() and is_external(
                attrs["href"]
            ):
                self.errors.append(
                    f"line {self.getpos()[0]}: external stylesheet is forbidden"
                )
        elif tag == "meta":
            http_equiv = attrs.get("http-equiv", "").lower()
            name = attrs.get("name", "").lower()
            if http_equiv == "content-security-policy":
                self.csp = attrs.get("content", "")
            if name == "referrer":
                self.referrer = attrs.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self.in_inline_script = False
            self.inline_script_line = None

    def handle_data(self, data: str) -> None:
        if self.in_inline_script and data.strip():
            self.errors.append(
                f"line {self.inline_script_line}: inline JavaScript is forbidden"
            )


def validate_html() -> list[str]:
    errors: list[str] = []
    parser = SiteParser()
    parser.feed(INDEX.read_text(encoding="utf-8"))
    errors.extend(parser.errors)

    if parser.html_lang != "fr":
        errors.append("index.html: French must be the default html lang")
    if parser.referrer != "no-referrer":
        errors.append("index.html: referrer policy must be no-referrer")
    if not parser.csp:
        errors.append("index.html: missing Content-Security-Policy meta")
    else:
        directives: dict[str, str] = {}
        for part in parser.csp.split(";"):
            tokens = part.strip().split(maxsplit=1)
            if tokens:
                directives[tokens[0]] = tokens[1] if len(tokens) > 1 else ""
        for directive, required_value in REQUIRED_CSP.items():
            if directive not in directives:
                errors.append(f"index.html: CSP misses {directive}")
            elif required_value not in directives[directive].split():
                errors.append(
                    f"index.html: CSP {directive} misses {required_value}"
                )

    for attribute, value, line in parser.references:
        if value.lower().startswith("http://"):
            errors.append(f"line {line}: insecure external URL in {attribute}")
            continue
        if is_external(value):
            continue
        try:
            target = local_target(value)
        except ValueError as exc:
            errors.append(f"line {line}: {exc}")
            continue
        if target is not None and not target.exists():
            errors.append(f"line {line}: missing local asset {value!r}")

    return errors


def validate_text_files() -> list[str]:
    errors: list[str] = []
    text_files = sorted({
        path
        for root in PUBLIC_TEXT_ROOTS
        if root.exists()
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".css", ".html", ".js", ".json", ".svg", ".txt"}
    })
    for path in text_files:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)

        private_match = PRIVATE_IP.search(text)
        if private_match:
            errors.append(f"{relative}: contains a private IPv4 address")

        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{relative}: possible {label}")

        if path.suffix.lower() == ".js":
            for label, pattern in FORBIDDEN_JS.items():
                if pattern.search(text):
                    errors.append(f"{relative}: forbidden {label}")

    return errors


def validate_png_files() -> list[str]:
    errors: list[str] = []
    png_files = sorted({
        path
        for root in PUBLIC_PNG_ROOTS
        if root.exists()
        for path in root.rglob("*.png")
        if path.is_file()
    })

    for path in png_files:
        relative = path.relative_to(ROOT)
        payload = path.read_bytes()
        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            errors.append(f"{relative}: invalid PNG signature")
            continue

        offset = 8
        saw_ihdr = False
        saw_iend = False
        while offset < len(payload):
            if offset + 12 > len(payload):
                errors.append(f"{relative}: truncated PNG chunk")
                break

            length = struct.unpack(">I", payload[offset : offset + 4])[0]
            chunk_type = payload[offset + 4 : offset + 8]
            data_start = offset + 8
            data_end = data_start + length
            crc_end = data_end + 4
            if crc_end > len(payload):
                errors.append(f"{relative}: PNG chunk exceeds file boundary")
                break

            stored_crc = struct.unpack(">I", payload[data_end:crc_end])[0]
            computed_crc = zlib.crc32(chunk_type)
            computed_crc = zlib.crc32(payload[data_start:data_end], computed_crc)
            if stored_crc != computed_crc & 0xFFFFFFFF:
                errors.append(
                    f"{relative}: invalid CRC in {chunk_type.decode('ascii', 'replace')} chunk"
                )

            if chunk_type == b"IHDR":
                if saw_ihdr or offset != 8 or length != 13:
                    errors.append(f"{relative}: invalid IHDR placement or size")
                saw_ihdr = True
                width, height = struct.unpack(">II", payload[data_start : data_start + 8])
                if not width or not height or width > 10000 or height > 10000:
                    errors.append(f"{relative}: unsafe PNG dimensions {width}x{height}")
            elif chunk_type == b"IEND":
                if length != 0:
                    errors.append(f"{relative}: invalid IEND size")
                saw_iend = True
                if crc_end != len(payload):
                    errors.append(f"{relative}: trailing data after IEND")
                break
            elif chunk_type in FORBIDDEN_PNG_CHUNKS:
                errors.append(
                    f"{relative}: contains {FORBIDDEN_PNG_CHUNKS[chunk_type]}"
                )

            offset = crc_end

        if not saw_ihdr:
            errors.append(f"{relative}: missing IHDR chunk")
        if not saw_iend:
            errors.append(f"{relative}: missing IEND chunk")

    return errors


def validate_security_txt() -> list[str]:
    path = SITE / ".well-known" / "security.txt"
    if not path.exists():
        return ["site/.well-known/security.txt: missing"]
    text = path.read_text(encoding="utf-8")
    required = {"Contact:", "Expires:", "Canonical:", "Policy:"}
    missing = sorted(item for item in required if item not in text)
    return [f"security.txt: missing {item}" for item in missing]


def main() -> int:
    errors = (
        validate_html()
        + validate_text_files()
        + validate_png_files()
        + validate_security_txt()
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    file_count = sum(1 for path in SITE.rglob("*") if path.is_file())
    print(f"OK: static portfolio security and integrity validated ({file_count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
