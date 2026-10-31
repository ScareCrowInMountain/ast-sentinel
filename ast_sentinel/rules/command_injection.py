"""
SEC002: Command Injection Detection.
Detects subprocess calls invoked with shell=True.
"""

from __future__ import annotations

import ast
from typing import List

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
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        is_subprocess_call = False
        func_name = ""

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and func_name in self.SUBPROCESS_FUNCS
            ):
                is_subprocess_call = True
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.SUBPROCESS_FUNCS:
                is_subprocess_call = True

        if is_subprocess_call:
            for kw in node.keywords:
                if kw.arg == "shell":
                    # shell=True detected
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(
                            self.create_finding(
                                node,
                                file_path,
                                source_lines,
                                f"subprocess.{func_name}() invoked with shell=True is susceptible to command injection. Pass command arguments as a list.",
                                Severity.HIGH,
                            )
                        )

        return findings
