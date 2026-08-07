import json
import unittest
from pathlib import Path


class TlsPublicEvidenceTests(unittest.TestCase):
    def test_rotation_c_closes_the_kv_store_gate(self):
        evidence_path = Path("artifacts/public/tls-rotation-evidence-20260807.json")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

        self.assertEqual(evidence["status"], "passed_after_remediation")
        self.assertEqual(evidence["target"]["active_rotation"], "rotation-c")
        self.assertEqual(evidence["target"]["kv_store_status"], "ready")
        self.assertTrue(evidence["live_controls"]["kv_store_ready_after_rotation"])
        self.assertTrue(evidence["live_controls"]["ssl_client_and_server_purposes_verified"])

        rotation_c = evidence["certificate_profiles"]["rotation-c"]
        self.assertEqual(set(rotation_c["extended_key_usage"]), {"serverAuth", "clientAuth"})
        self.assertTrue(rotation_c["kv_store_compatible"])

        regression = evidence["dependency_regression_and_recovery"]
        self.assertEqual(regression["failure_gate"], "kv_store_status_failed")
        self.assertEqual(regression["final_status"], "ready")
        self.assertEqual(regression["backup_restore_status"], "Ready")

    def test_prior_rotations_are_not_misrepresented_as_kv_compatible(self):
        evidence_path = Path("artifacts/public/tls-rotation-evidence-20260807.json")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

        for rotation in ("rotation-a", "rotation-b"):
            with self.subTest(rotation=rotation):
                profile = evidence["certificate_profiles"][rotation]
                self.assertFalse(profile["kv_store_compatible"])
                self.assertEqual(profile["qualified_scope"], "web_and_management_only")


if __name__ == "__main__":
    unittest.main()
