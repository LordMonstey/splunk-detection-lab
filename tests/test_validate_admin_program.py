#!/usr/bin/env python3
"""Regression tests for the version-aware Splunk administration program gate."""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import validate_admin_program as validator  # noqa: E402


def named_check(report: dict[str, object], name: str) -> dict[str, object]:
    return next(item for item in report["checks"] if item["name"] == name)


class AdminProgramIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        app_conf = (ROOT / validator.APP_CONF).read_text(encoding="utf-8")
        match = re.search(r"(?m)^version\s*=\s*(\S+)\s*$", app_conf)
        if not match:
            self.fail("current application version is absent from app.conf")
        self.current_version = match.group(1)
        major, minor, patch = (int(value) for value in self.current_version.split("."))
        self.next_version = f"{major}.{minor}.{patch + 1}"

    def copy_required_assets(self, target: Path) -> None:
        for relative in validator.required_assets():
            source = ROOT / relative
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def set_versions(self, target: Path, app_version: str, documented_version: str) -> None:
        app_conf = target / validator.APP_CONF
        app_conf.write_text(
            app_conf.read_text(encoding="utf-8").replace(
                f"version = {self.current_version}", f"version = {app_version}"
            ),
            encoding="utf-8",
        )
        assurance = target / validator.PLATFORM_ASSURANCE
        assurance.write_text(
            assurance.read_text(encoding="utf-8").replace(
                f"| Application | {self.current_version} |",
                f"| Application | {documented_version} |",
            ),
            encoding="utf-8",
        )

    def test_current_application_identity_passes(self) -> None:
        report = validator.validate(ROOT)
        identity = named_check(report, "admin_first_application_identity")
        self.assertEqual(identity["status"], "passed")
        self.assertIn(f"version={self.current_version}", identity["detail"])
        self.assertEqual(report["summary"]["status"], "passed")

    def test_future_semantic_version_is_derived_not_hardcoded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            self.copy_required_assets(target)
            self.set_versions(target, self.next_version, self.next_version)
            report = validator.validate(target)
        identity = named_check(report, "admin_first_application_identity")
        self.assertEqual(identity["status"], "passed")
        self.assertIn(f"version={self.next_version}", identity["detail"])

    def test_documentation_version_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            self.copy_required_assets(target)
            self.set_versions(target, self.next_version, self.current_version)
            report = validator.validate(target)
        identity = named_check(report, "admin_first_application_identity")
        self.assertEqual(identity["status"], "failed")
        self.assertIn(
            f"documented_version={self.current_version}", identity["detail"]
        )

    def test_non_semantic_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            self.copy_required_assets(target)
            self.set_versions(target, "release-current", "release-current")
            report = validator.validate(target)
        identity = named_check(report, "admin_first_application_identity")
        self.assertEqual(identity["status"], "failed")


if __name__ == "__main__":
    unittest.main()
