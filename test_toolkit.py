import unittest
from recon_toolkit.header_audit import SecurityHeaderAuditor
from recon_toolkit.reporter import HTMLReportGenerator

class TestReconToolkit(unittest.TestCase):

    def test_header_auditor_weights(self):
        self.assertIn("Strict-Transport-Security", SecurityHeaderAuditor.RECOMMENDED_HEADERS)
        self.assertIn("Content-Security-Policy", SecurityHeaderAuditor.RECOMMENDED_HEADERS)

    def test_html_reporter(self):
        mock_audit = {
            "target": "https://example.com",
            "score": 90,
            "grade": "A",
            "present_headers": {"Content-Security-Policy": "default-src 'self'"},
            "missing_headers": {}
        }
        html = HTMLReportGenerator.generate(mock_audit)
        self.assertIn("Security Recon Toolkit - Audit Report", html)
        self.assertIn("badge-A", html)
        self.assertIn("https://example.com", html)

if __name__ == "__main__":
    unittest.main()
