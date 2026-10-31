"""
SEC002: Command Injection Detection.
Detects subprocess calls invoked with shell=True.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class SubprocessShellRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC002",
        name="Subprocess Shell True",
        description="Detects subprocess calls invoked with shell=True, which can lead to command injection.",
        cwe_id="CWE-78",
        default_severity=Severity.HIGH,
    )

    SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        if mod == "subprocess" and func in self.SUBPROCESS_FUNCS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    finding = self.create_finding(
                        node,
                        context,
                        f"subprocess.{func}() invoked with shell=True is susceptible to command injection. Pass command arguments as a list.",
                        Severity.HIGH,
                    )
                    if finding:
                        findings.append(finding)

        return findings
