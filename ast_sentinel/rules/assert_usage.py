"""
SEC012: Insecure Assertion Usage Detection.
Detects assert statements outside test suites that can be stripped in optimized bytecode (python -O).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class AssertUsageRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC012",
        name="Unsafe Assert Usage",
        description="Detects assert statements in production code that are stripped when running python -O.",
        cwe_id="CWE-617",
        default_severity=Severity.LOW,
    )

    def check_assert(
        self,
        node: ast.Assert,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Do not flag assertions in actual test suites (test_*.py or *_test.py)
        file_name = Path(context.file_path).name.lower()
        if file_name.startswith("test_") or file_name.endswith("_test.py"):
            return findings

        finding = self.create_finding(
            node,
            context,
            "Use of 'assert' detected. Assertions are stripped in optimized mode (python -O) and must not be used for security or access control checks.",
            Severity.LOW,
        )
        if finding:
            findings.append(finding)

        return findings
