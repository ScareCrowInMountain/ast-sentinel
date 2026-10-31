"""
SEC005: Insecure Temporary File Creation Detection.
Detects usage of tempfile.mktemp which is vulnerable to symlink race conditions.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class InsecureTempFileRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC005",
        name="Insecure Temporary File",
        description="Detects tempfile.mktemp() which is vulnerable to race conditions.",
        cwe_id="CWE-377",
        default_severity=Severity.MEDIUM,
    )

    def check_call(
        self,
        node: ast.Call,
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile":
                if node.func.attr == "mktemp":
                    findings.append(
                        self.create_finding(
                            node,
                            file_path,
                            source_lines,
                            "tempfile.mktemp() is deprecated and susceptible to symlink/TOCTOU race conditions. Use tempfile.NamedTemporaryFile() instead.",
                            Severity.MEDIUM,
                        )
                    )

        return findings
