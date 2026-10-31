"""
Comprehensive unit test suite for AST-Sentinel.
Compatible with both standard unittest and pytest.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ast_sentinel.auditor import CodeAuditor
from ast_sentinel.config import SentinelConfig
from ast_sentinel.formatters.sarif import generate_sarif_report
from ast_sentinel.models import Severity

SAMPLES_DIR = Path(__file__).parent / "samples"


class TestASTSentinel(unittest.TestCase):
    def test_vulnerable_sample_triggers_all_rules(self):
        target = SAMPLES_DIR / "vulnerable_sample.py"
        auditor = CodeAuditor(min_severity=Severity.LOW)
        report = auditor.audit_path(target)

        self.assertEqual(report.files_scanned, 1)
        rule_ids = {f.rule_id for f in report.findings}

        expected_rules = {
            "SEC001",  # Arbitrary Code Execution
            "SEC002",  # Command Injection
            "SEC003",  # Weak Hash
            "SEC004",  # Insecure Deserialization
            "SEC005",  # Insecure Tempfile
            "SEC006",  # Hardcoded Secrets
            "SEC007",  # SQL Injection
            "SEC008",  # XXE
            "SEC009",  # Bind 0.0.0.0
            "SEC010",  # Disabled SSL
            "SEC011",  # Weak Random
            "SEC012",  # Unsafe Assert
            "SEC013",  # Archive Slip
            "SEC014",  # Debug Mode
            "SEC015",  # Path Traversal
        }

        for rule in expected_rules:
            self.assertIn(rule, rule_ids, f"Expected rule {rule} was not triggered in vulnerable_sample.py")

        for f in report.findings:
            self.assertGreater(f.line_number, 0)
            self.assertIsNotNone(f.snippet)
            self.assertTrue(f.cwe_id.startswith("CWE-"))

    def test_safe_sample_has_zero_false_positives(self):
        target = SAMPLES_DIR / "safe_sample.py"
        auditor = CodeAuditor(min_severity=Severity.LOW)
        report = auditor.audit_path(target)

        self.assertEqual(report.files_scanned, 1)
        # Should have 0 findings (including verified suppression of eval on last line)
        self.assertEqual(len(report.findings), 0)

    def test_import_alias_resolution(self):
        code = (
            "import subprocess as sp\n"
            "sp.call('ls', shell=True)\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            auditor = CodeAuditor()
            report = auditor.audit_file(tmp_path)
            rule_ids = {finding.rule_id for finding in report}
            self.assertIn("SEC002", rule_ids)
        finally:
            tmp_path.unlink()

    def test_from_import_alias_resolution(self):
        code = (
            "from subprocess import Popen as my_popen\n"
            "my_popen('echo hello', shell=True)\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            auditor = CodeAuditor()
            report = auditor.audit_file(tmp_path)
            rule_ids = {finding.rule_id for finding in report}
            self.assertIn("SEC002", rule_ids)
        finally:
            tmp_path.unlink()

    def test_inline_comment_suppression(self):
        code = (
            "eval('user_input')  # nosec\n"
            "eval('user_input2')  # sentinel: ignore=SEC001\n"
            "eval('user_input3')\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            auditor = CodeAuditor()
            findings = auditor.audit_file(tmp_path)
            # Only the 3rd eval should be reported
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].line_number, 3)
        finally:
            tmp_path.unlink()

    def test_sarif_v210_validity(self):
        target = SAMPLES_DIR / "vulnerable_sample.py"
        auditor = CodeAuditor()
        report = auditor.audit_path(target)

        sarif = generate_sarif_report(report, repo_root=str(SAMPLES_DIR))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "AST-Sentinel")
        self.assertGreater(len(run["tool"]["driver"]["rules"]), 10)
        self.assertGreater(len(run["results"]), 10)

        # Validate JSON serialization
        serialized = json.dumps(sarif)
        self.assertIsInstance(serialized, str)

    def test_config_ignore_rules(self):
        config = SentinelConfig(ignore_rules={"SEC001", "SEC002"})
        auditor = CodeAuditor(config=config)
        target = SAMPLES_DIR / "vulnerable_sample.py"
        report = auditor.audit_path(target)

        rule_ids = {f.rule_id for f in report.findings}
        self.assertNotIn("SEC001", rule_ids)
        self.assertNotIn("SEC002", rule_ids)

    def test_severity_threshold_filtering(self):
        target = SAMPLES_DIR / "vulnerable_sample.py"
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
