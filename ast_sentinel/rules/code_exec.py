"""
SEC001: Arbitrary Code Execution Detection.
Detects dangerous dynamic execution functions (eval, exec, os.system, os.popen).
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class ArbitraryCodeExecRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC001",
        name="Arbitrary Code Execution",
        description="Detects invocation of dynamic code execution functions like eval(), exec(), and os.system().",
        cwe_id="CWE-95",
        default_severity=Severity.CRITICAL,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        # Built-in eval / exec
        if mod is None and func in ("eval", "exec"):
            finding = self.create_finding(
                node,
                context,
                f"Use of built-in '{func}()' enables dynamic code evaluation, posing severe code injection risks.",
                Severity.CRITICAL,
            )
            if finding:
                findings.append(finding)

        # os.system / os.popen / posix.system
        elif mod in ("os", "posix") and func in ("system", "popen"):
            finding = self.create_finding(
                node,
                context,
                f"Direct call to '{mod}.{func}()' executes commands in a system subshell. Prefer subprocess.run with arguments list.",
                Severity.HIGH,
            )
            if finding:
                findings.append(finding)

        return findings
