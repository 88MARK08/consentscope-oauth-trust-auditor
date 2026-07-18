import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from consentscope import (
    load_scope_catalog,
    parse_authorization_request,
    analyze_request,
    risk_score,
)


class TestConsentScope(unittest.TestCase):
    def setUp(self):
        self.catalog = load_scope_catalog(PROJECT_ROOT / "rules" / "scope_catalog.json")

    def read_example(self, filename):
        path = PROJECT_ROOT / "examples" / filename
        return path.read_text(encoding="utf-8").strip()

    def test_safe_request_has_no_high_findings(self):
        raw_url = self.read_example("safe-request.txt")
        req = parse_authorization_request(raw_url)
        findings = analyze_request(req, self.catalog, "public")

        severities = [finding["severity"] for finding in findings]

        self.assertNotIn("HIGH", severities)
        self.assertLessEqual(risk_score(findings), 15)

    def test_broad_access_request_detects_major_risks(self):
        raw_url = self.read_example("broad-access-request.txt")
        req = parse_authorization_request(raw_url)
        findings = analyze_request(req, self.catalog, "public")

        rule_ids = {finding["rule_id"] for finding in findings}

        self.assertIn("redirect-uri-insecure", rule_ids)
        self.assertIn("state-missing", rule_ids)
        self.assertIn("pkce-missing", rule_ids)
        self.assertIn("scope-mail.read", rule_ids)
        self.assertIn("scope-mail.send", rule_ids)
        self.assertEqual(risk_score(findings), 100)

    def test_unknown_scope_is_detected(self):
        raw_url = self.read_example("insecure-request.txt")
        req = parse_authorization_request(raw_url)
        findings = analyze_request(req, self.catalog, "public")

        rule_ids = {finding["rule_id"] for finding in findings}

        self.assertIn("unknown-scope", rule_ids)
        self.assertIn("redirect-uri-insecure", rule_ids)
        self.assertIn("pkce-method-not-s256", rule_ids)


if __name__ == "__main__":
    unittest.main()
