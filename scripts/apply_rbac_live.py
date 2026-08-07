#!/usr/bin/env python3
"""Apply and exercise the version-compatible Splunk RBAC contract over REST.

The administrative password is read from a prompt or removed from this
process's environment. Ephemeral test passwords are generated in memory and
are never logged or written to the evidence artifact. A successful apply
leaves the six target roles in place and removes every test identity and test
object. A failed apply removes roles created by that run after cleanup.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import ssl
import string
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlparse
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener, urlopen

from validate_rbac_contract import (
    AUTHORIZE,
    EXPECTED_COMMON_CAPABILITY_COUNT,
    MATRIX,
    ROLE_SETTINGS,
    ROLES,
    SPLUNK_9_4_13_INCOMPATIBLE_CAPABILITIES,
    capabilities,
    load_authorize,
    split_semicolon,
    validate,
)


SUPPORTED_VERSIONS = ("9.4.13", "10.2.1")
ADMIN_REQUIRED_CAPABILITIES = {
    "admin_all_objects",
    "change_authentication",
    "edit_roles",
    "edit_user",
}
ROLE_CONFIG_PATH = "/services/configs/conf-authorize"
ROLE_API_PATH = "/services/authorization/roles"
CAPABILITY_API_PATH = "/services/authorization/capabilities"
USER_API_PATH = "/services/authentication/users"
AUTH_RELOAD_PATH = "/services/configs/conf-authorize/_reload"

ROLE_TEST_INDEX = {
    "platform_admin": "os_linux",
    "platform_operator": "_internal",
    "detection_engineer": "os_linux",
    "soc_analyst": "os_linux",
    "audit_reader": "_audit",
}
ROLE_FORBIDDEN_INDEX = {
    "platform_admin": "_thefishbucket",
    "platform_operator": "os_linux",
    "detection_engineer": "_audit",
    "soc_analyst": "_audit",
    "audit_reader": "_internal",
    "api_health": "_internal",
}

AUTHORIZATION_ERROR = re.compile(
    r"(?i)(?:not\s+authori[sz]ed|unauthori[sz]ed|permission\s+denied|"
    r"insufficient\s+(?:permission|privilege)|requires?\s+(?:the\s+)?"
    r"[a-z0-9_ -]*capabilit|cannot\s+search\s+index|do\s+not\s+have\s+"
    r"permission|not\s+allowed\s+to)"
)
PRIVATE_IPV4 = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
PUBLIC_FORBIDDEN_KEYS = re.compile(
    r"(?i)(?:^|_)(?:username|user_name|principal_name|password|passwd|secret|"
    r"token|session|sid|url|uri|hostname|host_name|address|response|raw|"
    r"message|path)(?:$|_)"
)
PUBLIC_FORBIDDEN_TEXT = (
    PRIVATE_IPV4,
    re.compile(r"(?i)https?://"),
    re.compile(r"(?i)\b(?:password|passwd|secret|token)\s*[:=]"),
    re.compile(r"(?i)\brbac_(?:user|role|saved)_?[a-f0-9]{6,}\b"),
)


@dataclass(frozen=True)
class HttpResult:
    status: int
    payload: Any
    body: str


@dataclass(frozen=True)
class RoleDefinition:
    name: str
    settings: dict[str, str]
    capabilities: tuple[str, ...]

    @property
    def stanza(self) -> str:
        return f"role_{self.name}"

    def create_form(self) -> list[tuple[str, str]]:
        fields: list[tuple[str, str]] = [("name", self.stanza)]
        fields.extend(sorted(self.settings.items()))
        fields.extend((capability, "enabled") for capability in self.capabilities)
        return fields

    def create_rest_form(self) -> list[tuple[str, str]]:
        fields: list[tuple[str, str]] = [("name", self.name)]
        for key, value in sorted(self.settings.items()):
            if key in {"srchIndexesAllowed", "srchIndexesDefault", "srchIndexesDisallowed"}:
                fields.extend((key, item) for item in sorted(split_semicolon(value)))
            else:
                fields.append((key, value))
        fields.extend(("capabilities", capability) for capability in self.capabilities)
        return fields


class RestClient:
    """Small urllib client supporting management-port and Splunk Web proxy REST."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        transport: str,
        verify_tls: bool,
        ca_bundle: str | None,
        allow_http: bool,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("--url must be an absolute HTTP or HTTPS origin")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("--url must not include a path, query, or fragment")
        if parsed.scheme != "https" and not allow_http:
            raise ValueError("plaintext HTTP requires the explicit --allow-http override")
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.headers = {"User-Agent": "splunk-detection-lab-rbac/1.0"}
        self.cookie_jar: CookieJar | None = None
        self.opener = None
        self.ssl_context = (
            ssl.create_default_context(cafile=ca_bundle)
            if verify_tls
            else ssl._create_unverified_context()
        )

        if transport == "management":
            encoded = base64.b64encode(f"{username}:{password}".encode("utf-8"))
            self.headers["Authorization"] = f"Basic {encoded.decode('ascii')}"
        elif transport == "web":
            self._login_web(username, password)
        else:
            raise ValueError(f"unsupported transport: {transport}")

    def _login_web(self, username: str, password: str) -> None:
        self.cookie_jar = CookieJar()
        handlers: list[Any] = [HTTPCookieProcessor(self.cookie_jar)]
        if self.base_url.lower().startswith("https://"):
            handlers.append(HTTPSHandler(context=self.ssl_context))
        self.opener = build_opener(*handlers)
        login_url = f"{self.base_url}/en-US/account/login"
        with self.opener.open(Request(login_url, headers=self.headers), timeout=20):
            pass
        challenge = next(
            (cookie.value for cookie in self.cookie_jar if cookie.name == "cval"), ""
        )
        if not challenge:
            raise RuntimeError("Splunk Web login challenge cookie is missing")
        body = urlencode(
            {
                "username": username,
                "password": password,
                "cval": challenge,
                "return_to": "/en-US/",
            }
        ).encode("utf-8")
        request = Request(
            login_url,
            headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=body,
            method="POST",
        )
        with self.opener.open(request, timeout=30):
            pass
        csrf = next(
            (
                cookie.value
                for cookie in self.cookie_jar
                if cookie.name.startswith("splunkweb_csrf_token_")
            ),
            "",
        )
        if not csrf:
            raise RuntimeError("Splunk Web session did not issue a CSRF token")
        self.headers["X-Splunk-Form-Key"] = unquote(csrf)
        self.headers["X-Requested-With"] = "XMLHttpRequest"

    def _url(self, path: str, query: Sequence[tuple[str, str]]) -> str:
        if not path.startswith("/services"):
            raise ValueError("only Splunk REST service paths are accepted")
        prefix = "/en-US/splunkd/__raw" if self.transport == "web" else ""
        encoded = urlencode(query, doseq=True)
        return f"{self.base_url}{prefix}{path}" + (f"?{encoded}" if encoded else "")

    def _open(self, request: Request, timeout: int):
        if self.opener is not None:
            return self.opener.open(request, timeout=timeout)
        return urlopen(request, timeout=timeout, context=self.ssl_context)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        data: Mapping[str, Any] | Sequence[tuple[str, Any]] | None = None,
        timeout: int = 30,
    ) -> HttpResult:
        query = [("output_mode", "json"), *params]
        encoded: bytes | None = None
        headers = dict(self.headers)
        if data is not None:
            encoded = urlencode(data, doseq=True).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(
            self._url(path, query),
            headers=headers,
            data=encoded,
            method=method,
        )
        try:
            with self._open(request, timeout) as response:
                status = int(response.status)
                body = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            status = int(exc.code)
            body = exc.read().decode("utf-8", errors="replace")
        except URLError as exc:
            raise RuntimeError("Splunk REST transport failed") from exc
        try:
            payload = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            payload = None
        return HttpResult(status=status, payload=payload, body=body)

    def get(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout: int = 30,
    ) -> HttpResult:
        return self.request("GET", path, params=params, timeout=timeout)

    def post(
        self,
        path: str,
        data: Mapping[str, Any] | Sequence[tuple[str, Any]],
        *,
        timeout: int = 30,
    ) -> HttpResult:
        return self.request("POST", path, data=data, timeout=timeout)

    def delete(self, path: str, *, timeout: int = 30) -> HttpResult:
        return self.request("DELETE", path, timeout=timeout)

    def close(self) -> None:
        self.headers.clear()
        if self.cookie_jar is not None:
            self.cookie_jar.clear()
        self.cookie_jar = None
        self.opener = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def entries(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    raw = payload.get("entry", [])
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def first_content(result: HttpResult) -> dict[str, Any]:
    result_entries = entries(result.payload)
    if not result_entries:
        return {}
    content = result_entries[0].get("content", {})
    return content if isinstance(content, dict) else {}


def iter_message_texts(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in {"text", "message", "messages"} and isinstance(child, str):
                yield child
            else:
                yield from iter_message_texts(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_message_texts(child)


def is_success(result: HttpResult) -> bool:
    if not 200 <= result.status < 300:
        return False
    messages = " ".join(iter_message_texts(result.payload))
    return not AUTHORIZATION_ERROR.search(messages)


def denial_signal(result: HttpResult) -> str | None:
    if result.status in {401, 403}:
        return "http_authorization_denial"
    if result.status == 404:
        return "protected_endpoint_concealment"
    message_text = " ".join(iter_message_texts(result.payload))
    if AUTHORIZATION_ERROR.search(message_text):
        return "splunk_authorization_error"
    if AUTHORIZATION_ERROR.search(result.body[:4096]):
        return "splunk_authorization_error"
    return None


def require_success(result: HttpResult, operation: str) -> None:
    if not is_success(result):
        raise RuntimeError(f"{operation} failed with HTTP {result.status}")


def make_password(length: int = 28) -> str:
    if length < 20:
        raise ValueError("ephemeral passwords must contain at least 20 characters")
    alphabet = string.ascii_letters + string.digits + "!%+,-.:=@_"
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!%+,-.:=@_"),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def random_name(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(7)}"


def load_contract(root: Path) -> list[RoleDefinition]:
    parser = load_authorize(root / AUTHORIZE)
    definitions: list[RoleDefinition] = []
    for role in ROLES:
        section = parser[f"role_{role}"]
        role_settings = {
            key: value
            for key, value in section.items()
            if key in ROLE_SETTINGS and key not in {"importRoles", "grantableRoles"}
        }
        definitions.append(
            RoleDefinition(
                name=role,
                settings=role_settings,
                capabilities=tuple(sorted(capabilities(parser, role))),
            )
        )
    return definitions


def capability_inventory(result: HttpResult) -> set[str]:
    require_success(result, "capability inventory")
    found: set[str] = set()
    if isinstance(result.payload, dict):
        root_caps = result.payload.get("capabilities")
        if isinstance(root_caps, list):
            found.update(str(item) for item in root_caps)
    for entry in entries(result.payload):
        content = entry.get("content", {})
        if isinstance(content, dict):
            raw_caps = content.get("capabilities")
            if isinstance(raw_caps, list):
                found.update(str(item) for item in raw_caps)
        name = entry.get("name")
        if isinstance(name, str) and name and name != "capabilities":
            found.add(name)
    if not found:
        raise RuntimeError("capability inventory returned no capability names")
    return found


def server_metadata(client: RestClient) -> dict[str, Any]:
    result = client.get("/services/server/info")
    require_success(result, "server metadata")
    content = first_content(result)
    version = str(content.get("version", ""))
    if version not in SUPPORTED_VERSIONS:
        raise RuntimeError(
            f"unsupported Splunk version {version or 'unknown'}; expected 9.4.13 or 10.2.1"
        )
    license_group = str(content.get("activeLicenseGroup", ""))
    if license_group.lower() == "free":
        raise RuntimeError("Splunk Free does not provide the required RBAC authentication features")
    return {
        "version": version,
        "build": str(content.get("build", "")),
        "product_type": str(content.get("product_type", "")),
        "enterprise_authentication_active": True,
    }


def admin_preflight(client: RestClient) -> None:
    result = client.get("/services/authentication/current-context")
    require_success(result, "administrative current context")
    content = first_content(result)
    effective = {str(item) for item in content.get("capabilities", [])}
    missing = sorted(ADMIN_REQUIRED_CAPABILITIES - effective)
    if missing:
        raise RuntimeError(f"administrative principal lacks required capabilities: {missing}")


def normalize_scope(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return split_semicolon(str(value))


def read_role_state(client: RestClient, role: RoleDefinition) -> tuple[dict[str, Any], dict[str, Any]] | None:
    api_result = client.get(f"{ROLE_API_PATH}/{quote(role.name, safe='')}")
    if api_result.status == 404:
        return None
    require_success(api_result, f"read role {role.name}")
    config_result = client.get(f"{ROLE_CONFIG_PATH}/{quote(role.stanza, safe='')}")
    if config_result.status == 404:
        api_content = first_content(api_result)
        return api_content, api_content
    require_success(config_result, f"read role configuration {role.name}")
    return first_content(api_result), first_content(config_result)


def role_drift(
    role: RoleDefinition,
    state: tuple[dict[str, Any], dict[str, Any]],
) -> list[str]:
    api_content, config_content = state
    drift: list[str] = []
    actual_capabilities = {str(item) for item in api_content.get("capabilities", [])}
    if actual_capabilities != set(role.capabilities):
        drift.append("capabilities")
    imported_roles = {str(item) for item in api_content.get("imported_roles", [])}
    if imported_roles:
        drift.append("imported_roles")
    for key, expected in role.settings.items():
        actual = config_content.get(key)
        if key in {"srchIndexesAllowed", "srchIndexesDefault", "srchIndexesDisallowed"}:
            if normalize_scope(actual) != split_semicolon(expected):
                drift.append(key)
        elif str(actual).strip() != expected.strip():
            drift.append(key)
    return sorted(set(drift))


def reload_authentication(client: RestClient) -> None:
    result = client.post(AUTH_RELOAD_PATH, {})
    require_success(result, "authentication reload")


def wait_for_role(
    client: RestClient,
    role: RoleDefinition,
    *,
    timeout: float = 30.0,
) -> list[str]:
    deadline = time.monotonic() + timeout
    last_drift = ["role_not_visible"]
    while time.monotonic() < deadline:
        state = read_role_state(client, role)
        if state is not None:
            last_drift = role_drift(role, state)
            if not last_drift:
                return []
        time.sleep(0.5)
    return last_drift


def check_contract_against_live_capabilities(
    roles: Sequence[RoleDefinition],
    live_capabilities: set[str],
) -> dict[str, Any]:
    declared = set().union(*(set(role.capabilities) for role in roles))
    missing = sorted(declared - live_capabilities)
    incompatible = sorted(declared & SPLUNK_9_4_13_INCOMPATIBLE_CAPABILITIES)
    if missing or incompatible or len(declared) != EXPECTED_COMMON_CAPABILITY_COUNT:
        raise RuntimeError(
            "RBAC capability preflight failed: "
            f"unique={len(declared)}, missing={missing}, incompatible={incompatible}"
        )
    return {
        "declared_unique": len(declared),
        "target_available": len(live_capabilities),
        "missing": [],
        "version_incompatible": [],
    }


def current_context_test(client: RestClient, role: RoleDefinition) -> dict[str, Any]:
    result = client.get("/services/authentication/current-context")
    content = first_content(result) if is_success(result) else {}
    roles = {str(item) for item in content.get("roles", [])}
    effective_caps = {str(item) for item in content.get("capabilities", [])}
    passed = is_success(result) and roles == {role.name} and effective_caps == set(role.capabilities)
    return make_test(
        control_id="RBAC-CONTEXT",
        role=role.name,
        direction="positive",
        target_class="mono_role_current_context",
        expected="allow_exact_scope",
        observed="allow_exact_scope" if passed else "scope_mismatch",
        http_status=result.status,
        signal="exact_role_and_capability_set" if passed else "context_mismatch",
        passed=passed,
    )


def make_test(
    *,
    control_id: str,
    role: str,
    direction: str,
    target_class: str,
    expected: str,
    observed: str,
    http_status: int,
    signal: str,
    passed: bool,
) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "role": role,
        "direction": direction,
        "target_class": target_class,
        "expected": expected,
        "observed": observed,
        "http_status": http_status,
        "decision_signal": signal,
        "status": "passed" if passed else "failed",
    }


def positive_http_test(
    control_id: str,
    role: str,
    target_class: str,
    result: HttpResult,
) -> dict[str, Any]:
    passed = is_success(result)
    return make_test(
        control_id=control_id,
        role=role,
        direction="positive",
        target_class=target_class,
        expected="allow",
        observed="allow" if passed else "error",
        http_status=result.status,
        signal="http_success" if passed else "request_failed",
        passed=passed,
    )


def negative_http_test(
    control_id: str,
    role: str,
    target_class: str,
    result: HttpResult,
) -> dict[str, Any]:
    signal = denial_signal(result)
    passed = signal is not None
    return make_test(
        control_id=control_id,
        role=role,
        direction="negative",
        target_class=target_class,
        expected="deny",
        observed="deny" if passed else "not_explicitly_denied",
        http_status=result.status,
        signal=signal or "no_authorization_denial",
        passed=passed,
    )


def run_search(client: RestClient, index: str, *, realtime: bool = False) -> HttpResult:
    if realtime:
        search = f"search index={index} earliest=rt-1m latest=rt | head 1"
        mode = "normal"
    else:
        search = f"search index={index} earliest=-15m | head 1"
        mode = "oneshot"
    return client.post(
        "/services/search/jobs",
        {"search": search, "exec_mode": mode},
        timeout=90,
    )


def payload_sid(result: HttpResult) -> str:
    if isinstance(result.payload, dict):
        sid = result.payload.get("sid")
        return str(sid) if sid else ""
    return ""


def role_scope_denial_test(
    role: RoleDefinition,
    forbidden_index: str,
    search_result: HttpResult,
) -> dict[str, Any]:
    allowed = split_semicolon(role.settings.get("srchIndexesAllowed", ""))
    disallowed = split_semicolon(role.settings.get("srchIndexesDisallowed", ""))
    explicitly_excluded = forbidden_index in disallowed or (
        "*" not in allowed and forbidden_index not in allowed
    )
    results = search_result.payload.get("results") if isinstance(search_result.payload, dict) else None
    no_data_returned = isinstance(results, list) and not results
    explicit = denial_signal(search_result)
    passed = explicit is not None or (
        explicitly_excluded and is_success(search_result) and no_data_returned
    )
    return make_test(
        control_id="RBAC-INDEX-DENY",
        role=role.name,
        direction="negative",
        target_class="forbidden_index_search",
        expected="deny",
        observed="deny" if passed else "scope_not_proven",
        http_status=search_result.status,
        signal=(
            explicit
            or (
                "effective_role_scope_excludes_index_and_search_returns_no_data"
                if passed
                else "effective_scope_or_search_failed"
            )
        ),
        passed=passed,
    )


def realtime_denial_test(
    client: RestClient,
    role: RoleDefinition,
    index: str,
) -> tuple[dict[str, Any], str]:
    created = run_search(client, index, realtime=True)
    sid = payload_sid(created)
    if not sid:
        return negative_http_test(
            "RBAC-020", role.name, "realtime_search", created
        ), ""

    deadline = time.monotonic() + 15.0
    observed = created
    dispatch_state = ""
    is_failed = False
    while time.monotonic() < deadline:
        observed = client.get(f"/services/search/jobs/{quote(sid, safe='')}")
        content = first_content(observed)
        dispatch_state = str(content.get("dispatchState", "")).upper()
        raw_failed = content.get("isFailed")
        is_failed = (
            raw_failed is True
            or str(raw_failed).strip().lower() in {"1", "true", "yes"}
            or dispatch_state == "FAILED"
        )
        if is_failed or dispatch_state in {"DONE", "RUNNING"}:
            break
        time.sleep(0.25)

    explicit = denial_signal(observed)
    capability_absent = "rtsearch" not in set(role.capabilities)
    passed = capability_absent and (is_failed or explicit is not None)
    test = make_test(
        control_id="RBAC-020",
        role=role.name,
        direction="negative",
        target_class="realtime_search",
        expected="deny",
        observed="deny" if passed else "job_not_explicitly_denied",
        http_status=observed.status,
        signal=(
            explicit
            or ("realtime_job_failed_without_rtsearch" if is_failed else "realtime_job_not_failed")
        ),
        passed=passed,
    )
    return test, sid


def cleanup_delete(client: RestClient, path: str) -> bool:
    result = client.delete(path)
    return result.status in {200, 201, 204, 404}


def exercise_roles(
    admin: RestClient,
    roles: Sequence[RoleDefinition],
    *,
    base_url: str,
    transport: str,
    verify_tls: bool,
    ca_bundle: str | None,
    allow_http: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    role_passwords: dict[str, str] = {}
    role_usernames: dict[str, str] = {}
    role_clients: dict[str, RestClient] = {}
    created_users: list[str] = []
    unexpected_users: set[str] = set()
    unexpected_roles: set[str] = set()
    created_saved_searches: list[tuple[RestClient, str]] = []
    search_jobs: set[str] = set()
    tests: list[dict[str, Any]] = []
    cleanup_errors: list[str] = []

    try:
        for role in roles:
            username = random_name("rbac_user")
            password = make_password()
            role_usernames[role.name] = username
            role_passwords[role.name] = password
            result = admin.post(
                USER_API_PATH,
                {
                    "name": username,
                    "password": password,
                    "roles": role.name,
                    "force-change-pass": "false",
                },
            )
            require_success(result, f"create ephemeral user for {role.name}")
            created_users.append(username)

        for role in roles:
            role_clients[role.name] = RestClient(
                base_url,
                role_usernames[role.name],
                role_passwords[role.name],
                transport=transport,
                verify_tls=verify_tls,
                ca_bundle=ca_bundle,
                allow_http=allow_http,
            )
            role_passwords[role.name] = ""

        for role in roles:
            tests.append(current_context_test(role_clients[role.name], role))

        for role_name, index in ROLE_TEST_INDEX.items():
            result = run_search(role_clients[role_name], index)
            control = {
                "platform_operator": "RBAC-002",
                "audit_reader": "RBAC-003",
            }.get(role_name, "RBAC-001")
            tests.append(positive_http_test(control, role_name, "scoped_search", result))

        health_result = role_clients["api_health"].get("/services/server/health/splunkd")
        tests.append(positive_http_test("RBAC-004", "api_health", "platform_health", health_result))

        audit_users = role_clients["audit_reader"].get(USER_API_PATH, params=(("count", "0"),))
        tests.append(positive_http_test("RBAC-017", "audit_reader", "identity_inventory", audit_users))

        detection_user = role_usernames["detection_engineer"]
        saved_name = random_name("rbac_saved")
        saved_base = (
            f"/servicesNS/{quote(detection_user, safe='')}/search/saved/searches"
        )
        saved_result = role_clients["detection_engineer"].post(
            saved_base,
            {
                "name": saved_name,
                "search": "| makeresults | stats count",
                "disabled": "1",
                "is_scheduled": "1",
                "cron_schedule": "17 * * * *",
            },
        )
        if is_success(saved_result):
            saved_path = f"{saved_base}/{quote(saved_name, safe='')}"
            created_saved_searches.append((role_clients["detection_engineer"], saved_path))
            saved_read = role_clients["detection_engineer"].get(saved_path)
            saved_passed = is_success(saved_read)
            tests.append(
                positive_http_test(
                    "RBAC-014",
                    "detection_engineer",
                    "owned_scheduled_detection",
                    saved_read,
                )
            )
            if not saved_passed:
                cleanup_errors.append("saved_search_read")
        else:
            tests.append(
                positive_http_test(
                    "RBAC-014",
                    "detection_engineer",
                    "owned_scheduled_detection",
                    saved_result,
                )
            )

        for role in roles:
            client = role_clients[role.name]
            forbidden_index = ROLE_FORBIDDEN_INDEX[role.name]
            result = run_search(client, forbidden_index)
            tests.append(role_scope_denial_test(role, forbidden_index, result))

            candidate_user = random_name("rbac_user")
            candidate_password = make_password()
            user_result = client.post(
                USER_API_PATH,
                {
                    "name": candidate_user,
                    "password": candidate_password,
                    "roles": "user",
                    "force-change-pass": "false",
                },
            )
            candidate_password = ""
            if is_success(user_result):
                unexpected_users.add(candidate_user)
            tests.append(
                negative_http_test(
                    "RBAC-018",
                    role.name,
                    "identity_creation",
                    user_result,
                )
            )

            candidate_role = random_name("rbac_role")
            role_result = client.post(ROLE_API_PATH, {"name": candidate_role})
            if is_success(role_result):
                unexpected_roles.add(candidate_role)
            tests.append(
                negative_http_test(
                    "RBAC-019",
                    role.name,
                    "role_creation",
                    role_result,
                )
            )

            realtime_index = ROLE_TEST_INDEX.get(role.name, "_internal")
            realtime_test, sid = realtime_denial_test(client, role, realtime_index)
            if sid:
                search_jobs.add(sid)
            tests.append(realtime_test)
    finally:
        for client, saved_path in reversed(created_saved_searches):
            if not cleanup_delete(client, saved_path):
                cleanup_errors.append("saved_search_cleanup")
        for client in role_clients.values():
            client.close()
        for sid in search_jobs:
            if not cleanup_delete(admin, f"/services/search/jobs/{quote(sid, safe='')}"):
                cleanup_errors.append("search_job_cleanup")
        for username in unexpected_users:
            if not cleanup_delete(admin, f"{USER_API_PATH}/{quote(username, safe='')}"):
                cleanup_errors.append("unexpected_user_cleanup")
        for role_name in unexpected_roles:
            if not cleanup_delete(admin, f"{ROLE_API_PATH}/{quote(role_name, safe='')}"):
                cleanup_errors.append("unexpected_role_cleanup")
        removed_users = 0
        for username in reversed(created_users):
            if cleanup_delete(admin, f"{USER_API_PATH}/{quote(username, safe='')}"):
                removed_users += 1
            else:
                cleanup_errors.append("ephemeral_user_cleanup")
        for role in list(role_passwords):
            role_passwords[role] = ""
        role_passwords.clear()
        role_usernames.clear()

    cleanup = {
        "ephemeral_users_created": len(created_users),
        "ephemeral_users_removed": removed_users,
        "unexpected_users_removed": len(unexpected_users),
        "unexpected_roles_removed": len(unexpected_roles),
        "errors": sorted(set(cleanup_errors)),
        "status": (
            "passed"
            if removed_users == len(created_users) and not cleanup_errors
            else "failed"
        ),
    }
    return tests, cleanup


def scan_public_evidence(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if PUBLIC_FORBIDDEN_KEYS.search(key_text):
                findings.append(f"{path}.{key_text}:forbidden_key")
            findings.extend(scan_public_evidence(child, f"{path}.{key_text}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(scan_public_evidence(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        for pattern in PUBLIC_FORBIDDEN_TEXT:
            if pattern.search(value):
                findings.append(f"{path}:forbidden_text")
    return findings


def write_public_evidence(path: Path, evidence: dict[str, Any], *, overwrite: bool) -> None:
    findings = scan_public_evidence(evidence)
    if findings:
        raise RuntimeError(f"public evidence safety scan failed: {findings}")
    if path.exists() and not overwrite:
        raise FileExistsError(f"evidence already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def evidence_path(root: Path, version: str) -> Path:
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return root / "artifacts" / "public" / f"rbac-live-evidence-{version}-{date}.json"


def apply_and_test(
    args: argparse.Namespace,
    root: Path,
    roles: Sequence[RoleDefinition],
) -> int:
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    verify_tls = not args.insecure
    admin: RestClient | None = None
    created_roles: list[RoleDefinition] = []
    apply_records: list[dict[str, Any]] = []
    try:
        admin = RestClient(
            args.url,
            args.username,
            password,
            transport=args.transport,
            verify_tls=verify_tls,
            ca_bundle=str(args.ca_bundle) if args.ca_bundle else None,
            allow_http=args.allow_http,
        )
        password = ""
        target = server_metadata(admin)
        admin_preflight(admin)
        live_capabilities = capability_inventory(
            admin.get(CAPABILITY_API_PATH, params=(("count", "0"),))
        )
        compatibility = check_contract_against_live_capabilities(roles, live_capabilities)

        missing_roles: list[RoleDefinition] = []
        for role in roles:
            state = read_role_state(admin, role)
            if state is None:
                missing_roles.append(role)
                apply_records.append(
                    {
                        "role": role.name,
                        "action": "planned_create" if args.mode == "preflight" else "created",
                        "direct_capabilities": len(role.capabilities),
                        "status": "pending" if args.mode == "preflight" else "passed",
                    }
                )
                continue
            drift = role_drift(role, state)
            if drift:
                raise RuntimeError(f"existing role {role.name} drifts on: {drift}")
            apply_records.append(
                {
                    "role": role.name,
                    "action": "unchanged",
                    "direct_capabilities": len(role.capabilities),
                    "status": "passed",
                }
            )

        if args.mode == "preflight":
            print(
                json.dumps(
                    {
                        "status": "passed",
                        "mode": "preflight",
                        "splunk_version": target["version"],
                        "roles_missing": len(missing_roles),
                        "roles_exact": len(roles) - len(missing_roles),
                        "capabilities": compatibility,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0

        for role in missing_roles:
            result = admin.post(ROLE_API_PATH, role.create_rest_form())
            require_success(result, f"create role {role.name}")
            created_roles.append(role)

        for role in roles:
            drift = wait_for_role(admin, role)
            if drift:
                raise RuntimeError(f"effective role {role.name} failed verification: {drift}")
        for item in apply_records:
            if item["action"] == "created":
                item["status"] = "passed"

        tests, cleanup = exercise_roles(
            admin,
            roles,
            base_url=args.url,
            transport=args.transport,
            verify_tls=verify_tls,
            ca_bundle=str(args.ca_bundle) if args.ca_bundle else None,
            allow_http=args.allow_http,
        )
        failed_tests = [item for item in tests if item["status"] != "passed"]
        if failed_tests or cleanup["status"] != "passed":
            failed_summary = [
                {
                    "control_id": item["control_id"],
                    "role": item["role"],
                    "direction": item["direction"],
                    "http_status": item["http_status"],
                    "decision_signal": item["decision_signal"],
                }
                for item in failed_tests
            ]
            raise RuntimeError(
                "RBAC live qualification failed: "
                f"tests={len(failed_tests)}, cleanup={cleanup['status']}, "
                f"failures={json.dumps(failed_summary, sort_keys=True)}"
            )

        evidence = {
            "artifact_type": "splunk_rbac_live_evidence",
            "schema_version": 1,
            "generated_at_utc": utc_now(),
            "status": "passed",
            "target": {
                **target,
                "transport": args.transport,
                "tls_verified": verify_tls and args.url.lower().startswith("https://"),
            },
            "contract": {
                "authorize_sha256": sha256_file(root / AUTHORIZE),
                "matrix_sha256": sha256_file(root / MATRIX),
                "roles": len(roles),
                "capabilities": compatibility,
                "supported_versions": list(SUPPORTED_VERSIONS),
            },
            "application": apply_records,
            "tests": tests,
            "summary": {
                "positive": sum(item["direction"] == "positive" for item in tests),
                "negative": sum(item["direction"] == "negative" for item in tests),
                "passed": len(tests),
                "total": len(tests),
            },
            "cleanup": cleanup,
        }
        output = args.evidence_output or evidence_path(root, target["version"])
        write_public_evidence(output, evidence, overwrite=args.overwrite_evidence)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "splunk_version": target["version"],
                    "roles": len(roles),
                    "tests": len(tests),
                    "evidence": str(output),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    except Exception:
        if admin is not None and created_roles:
            rollback_errors: list[str] = []
            for role in reversed(created_roles):
                result = admin.delete(f"{ROLE_API_PATH}/{quote(role.name, safe='')}")
                if result.status not in {200, 201, 204, 404}:
                    rollback_errors.append(role.name)
            if rollback_errors:
                raise RuntimeError(f"RBAC rollback incomplete: {rollback_errors}")
        raise
    finally:
        password = ""
        if admin is not None:
            admin.close()


def run_self_test(root: Path) -> int:
    checks: list[tuple[str, bool]] = []
    static_report = validate(root)
    checks.append(("static_contract", static_report.get("status") == "passed"))
    roles = load_contract(root)
    declared = set().union(*(set(role.capabilities) for role in roles))
    checks.append(("role_inventory", len(roles) == len(ROLES)))
    checks.append(
        (
            "cross_version_capabilities",
            len(declared) == EXPECTED_COMMON_CAPABILITY_COUNT
            and not declared.intersection(SPLUNK_9_4_13_INCOMPATIBLE_CAPABILITIES),
        )
    )
    generated = make_password()
    checks.append(
        (
            "ephemeral_password_policy",
            len(generated) >= 20
            and any(char.islower() for char in generated)
            and any(char.isupper() for char in generated)
            and any(char.isdigit() for char in generated)
            and any(not char.isalnum() for char in generated),
        )
    )
    generated = ""
    checks.append(
        (
            "http_denial_classifier",
            denial_signal(HttpResult(403, {"messages": []}, ""))
            == "http_authorization_denial",
        )
    )
    checks.append(
        (
            "payload_denial_classifier",
            denial_signal(
                HttpResult(
                    400,
                    {"messages": [{"type": "ERROR", "text": "not authorized"}]},
                    "",
                )
            )
            == "splunk_authorization_error",
        )
    )
    checks.append(
        (
            "empty_result_is_not_denial",
            denial_signal(HttpResult(200, {"results": []}, "")) is None,
        )
    )
    safe_sample = {
        "status": "passed",
        "role": "soc_analyst",
        "target": {"version": "10.2.1"},
    }
    checks.append(("public_evidence_safe_sample", not scan_public_evidence(safe_sample)))
    unsafe_sample = {"target_url": "https://example.test", "status": "failed"}
    checks.append(("public_evidence_rejects_endpoint", bool(scan_public_evidence(unsafe_sample))))

    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    print(f"RBAC live harness self-test: {'passed' if not failed else 'failed'} ({len(checks) - len(failed)}/{len(checks)})")
    return 0 if not failed else 1


def offline_dry_run(root: Path) -> int:
    report = validate(root)
    if report.get("status") != "passed":
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1
    roles = load_contract(root)
    declared = set().union(*(set(role.capabilities) for role in roles))
    print(
        json.dumps(
            {
                "status": "passed",
                "mode": "offline_dry_run",
                "supported_versions": list(SUPPORTED_VERSIONS),
                "roles": len(roles),
                "unique_capabilities": len(declared),
                "ephemeral_users_planned": len(roles),
                "live_mutation": False,
                "evidence_written": False,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", dest="mode", action="store_const", const="dry-run")
    modes.add_argument("--self-test", dest="mode", action="store_const", const="self-test")
    modes.add_argument("--preflight", dest="mode", action="store_const", const="preflight")
    modes.add_argument("--apply", dest="mode", action="store_const", const="apply")
    parser.add_argument("--url", help="Splunk origin, without a path.")
    parser.add_argument("--username", default="admin", help="Administrative Splunk principal.")
    parser.add_argument(
        "--transport",
        choices=("management", "web"),
        default="management",
        help="Use the management API or the Splunk Web authenticated REST proxy.",
    )
    parser.add_argument("--ca-bundle", type=Path, help="CA bundle used to verify TLS.")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification for a bounded lab diagnostic only.",
    )
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="Allow plaintext HTTP for a bounded lab diagnostic only.",
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence-output", type=Path)
    parser.add_argument("--overwrite-evidence", action="store_true")
    args = parser.parse_args()
    if args.mode in {"preflight", "apply"} and not args.url:
        parser.error("--url is required with --preflight or --apply")
    if args.ca_bundle and args.insecure:
        parser.error("--ca-bundle and --insecure are mutually exclusive")
    if args.mode == "apply" and (
        args.insecure or args.allow_http or not args.url.lower().startswith("https://")
    ):
        parser.error("--apply requires HTTPS with certificate verification enabled")
    if args.mode != "apply" and (args.evidence_output or args.overwrite_evidence):
        parser.error("evidence options are valid only with --apply")
    return args


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if args.mode == "self-test":
        return run_self_test(root)
    if args.mode == "dry-run":
        return offline_dry_run(root)
    static_report = validate(root)
    if static_report.get("status") != "passed":
        raise RuntimeError("offline RBAC contract validation failed")
    roles = load_contract(root)
    return apply_and_test(args, root, roles)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FileExistsError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
