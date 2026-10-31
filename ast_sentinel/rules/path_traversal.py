"""
SEC015: Path Traversal via Unvalidated File Access Detection.
Detects direct concatenation of dynamic variables into file open calls.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class PathTraversalRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC015",
        name="Path Traversal in File Open",
        description="Detects dynamic string interpolation or concatenation directly inside open() calls.",
        cwe_id="CWE-22",
        default_severity=Severity.MEDIUM,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        if mod is None and func == "open" and node.args:
            first_arg = node.args[0]
            is_dynamic = False

            # Check if open() uses f-string with variables or + concatenation
            if isinstance(first_arg, ast.JoinedStr):
                # Has variable expressions inside
                has_expr = any(isinstance(v, ast.FormattedValue) for v in first_arg.values)
                if has_expr:
                    is_dynamic = True
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                is_dynamic = True

            if is_dynamic:
                lineno = getattr(node, "lineno", 0)
                line_str = context.source_lines[lineno - 1].lower() if 1 <= lineno <= len(context.source_lines) else ""
                # Avoid flagging if path normalization (abspath, resolve, realpath) is visibly present on same line
                if not any(sanitizer in line_str for sanitizer in ("resolve()", "abspath(", "realpath(")):
                    finding = self.create_finding(
                        node,
                        context,
                        "Dynamic path concatenation passed to open() without path validation. Ensure paths are resolved and restricted to a whitelist directory.",
                        Severity.MEDIUM,
                    )
                    if finding:
                        findings.append(finding)

        return findings
