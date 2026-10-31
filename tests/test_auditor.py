"""
Unit test suite for AST-Sentinel.
Compatible with both standard unittest and pytest.
"""

import tempfile
import unittest
from pathlib import Path

from ast_sentinel.auditor import CodeAuditor
from ast_sentinel.models import Severity

SAMPLES_DIR = Path(__file__).parent / "samples"


class TestASTSentinel(unittest.TestCase):
    def test_vulnerable_sample_triggers_all_rules(self):
        target = SAMPLES_DIR / "vulnerable_sample.py"
        auditor = CodeAuditor(min_severity=Severity.LOW)
        report = auditor.audit_path(target)

        self.assertEqual(report.files_scanned, 1)
        rule_ids = {f.rule_id for f in report.findings}

        # Verify all expected rules triggered
        self.assertIn("SEC001", rule_ids)  # eval / exec / os.system
        self.assertIn("SEC002", rule_ids)  # subprocess shell=True
        self.assertIn("SEC003", rule_ids)  # weak md5
        self.assertIn("SEC004", rule_ids)  # pickle / unsafe yaml
        self.assertIn("SEC005", rule_ids)  # tempfile.mktemp

        # Check finding metadata integrity
        for f in report.findings:
            self.assertGreater(f.line_number, 0)
            self.assertIsNotNone(f.snippet)
            self.assertTrue(f.cwe_id.startswith("CWE-"))

    def test_safe_sample_has_zero_false_positives(self):
        target = SAMPLES_DIR / "safe_sample.py"
        auditor = CodeAuditor(min_severity=Severity.LOW)
        report = auditor.audit_path(target)

        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(len(report.findings), 0)

    def test_severity_threshold_filtering(self):
        target = SAMPLES_DIR / "vulnerable_sample.py"

        # Only High and Critical
        auditor_high = CodeAuditor(min_severity=Severity.HIGH)
        report_high = auditor_high.audit_path(target)

        severities = {f.severity for f in report_high.findings}
        self.assertNotIn(Severity.LOW, severities)
        self.assertNotIn(Severity.MEDIUM, severities)
        self.assertTrue(Severity.HIGH in severities or Severity.CRITICAL in severities)

    def test_graceful_handling_of_syntax_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            broken_file = Path(tmp_dir) / "broken.py"
            broken_file.write_text("def broken_func(:\n    pass\n", encoding="utf-8")

            auditor = CodeAuditor()
            report = auditor.audit_path(broken_file)

            self.assertEqual(report.files_scanned, 1)
            self.assertEqual(len(report.findings), 1)
            self.assertEqual(report.findings[0].rule_id, "SYNTAX_ERR")

    def test_nonexistent_path_returns_error(self):
        fake_path = Path("/path/does/not/exist/surely_12345.py")
        auditor = CodeAuditor()
        report = auditor.audit_path(fake_path)

        self.assertGreater(len(report.errors), 0)
        self.assertEqual(report.files_scanned, 0)


if __name__ == "__main__":
    unittest.main()
