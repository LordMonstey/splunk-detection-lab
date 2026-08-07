#!/usr/bin/env python3
"""Offline regression tests for the Splunk RBAC live harness."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import apply_rbac_live as rbac  # noqa: E402


class RbacLiveHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.roles = rbac.load_contract(ROOT)

    def test_static_contract_is_valid(self) -> None:
        report = rbac.validate(ROOT)
        self.assertEqual("passed", report["status"])

    def test_capability_set_is_common_to_both_versions(self) -> None:
        declared = set().union(*(set(role.capabilities) for role in self.roles))
        self.assertEqual(rbac.EXPECTED_COMMON_CAPABILITY_COUNT, len(declared))
        self.assertFalse(
            declared.intersection(rbac.SPLUNK_9_4_13_INCOMPATIBLE_CAPABILITIES)
        )

    def test_role_form_contains_only_contract_fields(self) -> None:
        role = self.roles[0]
        fields = role.create_form()
        self.assertEqual(("name", role.stanza), fields[0])
        keys = [key for key, _ in fields]
        self.assertNotIn("username", keys)
        self.assertNotIn("password", keys)
        self.assertTrue(set(role.capabilities).issubset(keys))

    def test_role_rest_form_uses_role_endpoint_schema(self) -> None:
        role = self.roles[0]
        fields = role.create_rest_form()
        self.assertEqual(("name", role.name), fields[0])
        keys = [key for key, _ in fields]
        self.assertNotIn(role.capabilities[0], keys)
        self.assertEqual(len(role.capabilities), keys.count("capabilities"))
        self.assertNotIn("password", keys)

    def test_exact_role_state_has_no_drift(self) -> None:
        role = self.roles[0]
        state = (
            {"capabilities": list(role.capabilities), "imported_roles": []},
            dict(role.settings),
        )
        self.assertEqual([], rbac.role_drift(role, state))

    def test_role_drift_detects_capability_import_and_scope(self) -> None:
        role = self.roles[0]
        state = (
            {
                "capabilities": list(role.capabilities[:-1]),
                "imported_roles": ["user"],
            },
            dict(role.settings),
        )
        state[1]["srchIndexesAllowed"] = "main"
        self.assertEqual(
            ["capabilities", "imported_roles", "srchIndexesAllowed"],
            rbac.role_drift(role, state),
        )

    def test_http_403_is_an_explicit_denial(self) -> None:
        result = rbac.HttpResult(403, {"messages": []}, "")
        self.assertEqual("http_authorization_denial", rbac.denial_signal(result))

    def test_splunk_authorization_message_is_an_explicit_denial(self) -> None:
        result = rbac.HttpResult(
            400,
            {"messages": [{"type": "ERROR", "text": "not authorized"}]},
            "",
        )
        self.assertEqual("splunk_authorization_error", rbac.denial_signal(result))

    def test_empty_search_result_is_not_a_denial(self) -> None:
        result = rbac.HttpResult(200, {"results": []}, "")
        self.assertIsNone(rbac.denial_signal(result))

    def test_generated_passwords_meet_complexity_policy(self) -> None:
        values = {rbac.make_password() for _ in range(32)}
        self.assertEqual(32, len(values))
        for value in values:
            self.assertGreaterEqual(len(value), 20)
            self.assertTrue(any(char.islower() for char in value))
            self.assertTrue(any(char.isupper() for char in value))
            self.assertTrue(any(char.isdigit() for char in value))
            self.assertTrue(any(not char.isalnum() for char in value))

    def test_public_evidence_accepts_anonymous_counters(self) -> None:
        evidence = {
            "status": "passed",
            "target": {"version": "10.2.1", "tls_verified": True},
            "cleanup": {
                "ephemeral_users_created": 6,
                "ephemeral_users_removed": 6,
                "unexpected_users_removed": 0,
            },
        }
        self.assertEqual([], rbac.scan_public_evidence(evidence))

    def test_public_evidence_rejects_sensitive_material(self) -> None:
        samples = (
            {"username": "ephemeral"},
            {"target": "https://splunk.example.test"},
            {"target": "192.168.50.7"},
            {"detail": "token=example"},
            {"detail": "rbac_user_abcdef123456"},
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(rbac.scan_public_evidence(copy.deepcopy(sample)))

    def test_client_rejects_plaintext_without_override_before_network(self) -> None:
        with self.assertRaises(ValueError):
            rbac.RestClient(
                "http://splunk.example.test:8000",
                "principal",
                "not-persisted",
                transport="web",
                verify_tls=True,
                ca_bundle=None,
                allow_http=False,
            )


if __name__ == "__main__":
    unittest.main()
