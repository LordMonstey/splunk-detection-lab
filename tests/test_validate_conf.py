import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.validate_conf as validate_conf


class ValidateTlsPolicyTests(unittest.TestCase):
    def test_repository_tls_output_templates_pass(self):
        for path in (
            Path("conf/tls-examples/outputs.conf"),
            Path("conf/uf/outputs.conf"),
        ):
            with self.subTest(path=path):
                self.assertEqual(validate_conf.validate_tls_policy(path), [])

    def test_disabled_certificate_validation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.conf"
            path.write_text(
                "[sslConfig]\nsslVerifyServerCert = false\n",
                encoding="utf-8",
            )
            errors = validate_conf.validate_tls_policy(path)
        self.assertTrue(any("must never disable" in error for error in errors))

    def test_disabled_hostname_validation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.conf"
            path.write_text(
                "[sslConfig]\nsslVerifyServerName = false\n",
                encoding="utf-8",
            )
            errors = validate_conf.validate_tls_policy(path)
        self.assertTrue(any("must never disable" in error for error in errors))

    def test_reserved_receiver_names_and_sans_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outputs.conf"
            path.write_text(
                "[tcpout:test]\n"
                "server = 192.0.2.10:9997\n"
                "useSSL = true\n"
                "sslRootCAPath = $SPLUNK_HOME/etc/auth/ca.pem\n"
                "sslVerifyServerCert = true\n"
                "sslVerifyServerName = true\n"
                "sslAltNameToCheck = idx-a.example.invalid\n",
                encoding="utf-8",
            )
            with patch.object(validate_conf, "TLS_OUTPUT_TEMPLATES", {path.as_posix()}):
                errors = validate_conf.validate_tls_policy(path)
        self.assertTrue(any("example.invalid FQDN" in error for error in errors))
        self.assertTrue(any("must exactly match" in error for error in errors))

    def test_tls_output_requires_a_trust_store(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outputs.conf"
            path.write_text(
                "[tcpout:test]\n"
                "server = idx-a.example.invalid:9997\n"
                "useSSL = true\n"
                "sslVerifyServerCert = true\n"
                "sslVerifyServerName = true\n"
                "sslAltNameToCheck = idx-a.example.invalid\n",
                encoding="utf-8",
            )
            with patch.object(validate_conf, "TLS_OUTPUT_TEMPLATES", {path.as_posix()}):
                errors = validate_conf.validate_tls_policy(path)
        self.assertTrue(any("needs sslRootCAPath" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
