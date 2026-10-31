"""
SEC013: Archive Extraction Path Traversal (ZipSlip / TarSlip) Detection.
Detects archive extractall() invocations vulnerable to arbitrary file overwrite.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class ArchiveSlipRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC013",
        name="Archive Path Traversal (ZipSlip)",
        description="Detects extractall() on tar/zip archives without path sanitization (CWE-22).",
        cwe_id="CWE-22",
        default_severity=Severity.HIGH,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall":
            # Check if filter parameter is present (Python 3.12+ safe tarfile filter)
            has_safe_filter = any(
                kw.arg == "filter" and isinstance(kw.value, ast.Constant) and kw.value.value in ("data", "tar")
                for kw in node.keywords
            )
            if not has_safe_filter:
                finding = self.create_finding(
                    node,
                    context,
                    "Calling 'extractall()' on unvalidated archives risks directory traversal (ZipSlip/TarSlip). Validate member paths or use filter='data'.",
                    Severity.HIGH,
                )
                if finding:
                    findings.append(finding)

        return findings
