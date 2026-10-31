"""
SEC014: Debug Mode in Production Detection.
Detects active debug flags in frameworks (Flask, Django) exposing internal stack traces.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class DebugModeRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC014",
        name="Debug Mode Enabled",
        description="Detects active debug modes exposing interactive debuggers or sensitive stack traces.",
        cwe_id="CWE-489",
        default_severity=Severity.HIGH,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    finding = self.create_finding(
                        node,
                        context,
                        "Running web application with debug=True enables the interactive debugger and arbitrary code execution in production.",
                        Severity.CRITICAL,
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def check_assign(
        self,
        node: ast.Assign,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    finding = self.create_finding(
                        node,
                        context,
                        "DEBUG = True hardcoded. Ensure debug mode is toggled off in production deployments.",
                        Severity.HIGH,
                    )
                    if finding:
                        findings.append(finding)

        return findings
