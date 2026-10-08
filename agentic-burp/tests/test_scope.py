import unittest
import sys
import os

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models.scope import ScopePolicy
from scope.validator import ScopeValidator
from scope.resolver import normalize_url, extract_host_port


class TestScopeValidator(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            targets=["http://127.0.0.1:8080", "https://authorized-lab.example"],
            allowed_methods=["GET", "POST"],
            allowed_ports=[80, 443, 8080],
            allow_subdomains=False,
            allow_external_hosts=False,
            allow_internal_loopback=True,
        )
        self.validator = ScopeValidator(self.policy)

    def test_url_normalization(self):
        norm = normalize_url("http://127.0.0.1:8080/path?b=2&a=1#frag")
        self.assertEqual(norm, "http://127.0.0.1:8080/path?a=1&b=2")

    def test_in_scope_target(self):
        res = self.validator.validate_url("http://127.0.0.1:8080/api/users")
        self.assertTrue(res.allowed)

    def test_out_of_scope_target(self):
        res = self.validator.validate_url("http://malicious-external.example/evil")
        self.assertFalse(res.allowed)

    def test_disallowed_method(self):
        res = self.validator.validate_method("DELETE")
        self.assertFalse(res.allowed)
        res_ok = self.validator.validate_method("GET")
        self.assertTrue(res_ok.allowed)

    def test_ssrf_metadata_blocked(self):
        res = self.validator.validate_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(res.allowed)
        self.assertIn("metadata", res.reason.lower())

    def test_disallowed_port(self):
        res = self.validator.validate_url("http://127.0.0.1:22/ssh")
        self.assertFalse(res.allowed)


if __name__ == "__main__":
    unittest.main()
