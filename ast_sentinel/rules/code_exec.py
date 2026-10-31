"""
SEC001: Arbitrary Code Execution Detection.
Detects dangerous dynamic execution functions (eval, exec, os.system).
"""

from __future__ import annotations

import ast
from typing import List

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
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Case 1: Built-in eval(...) or exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            findings.append(
                self.create_finding(
                    node,
                    file_path,
                    source_lines,
                    f"Use of built-in '{node.func.id}()' enables dynamic code evaluation, posing severe code injection risks.",
                    Severity.CRITICAL,
                )
            )

        # Case 2: os.system(...) or os.popen(...)
        elif isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in ("system", "popen")
            ):
                findings.append(
                    self.create_finding(
                        node,
                        file_path,
                        source_lines,
                        f"Direct call to 'os.{node.func.attr}()' executes commands in a system subshell. Prefer subprocess.run with arguments list.",
                        Severity.HIGH,
                    )
                )

        return findings
