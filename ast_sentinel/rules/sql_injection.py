"""
SEC007: SQL Injection Detection.
Detects raw SQL queries constructed via string concatenation or interpolation.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


SQL_METHODS = {"execute", "executemany", "raw"}
SQL_KEYWORDS = {"select", "insert", "update", "delete", "where", "drop", "alter"}


def is_sql_string(text: str) -> bool:
    low = text.lower()
    return any(f"{kw} " in low or f" {kw}" in low for kw in SQL_KEYWORDS)


@register_rule
class SqlInjectionRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC007",
        name="SQL Injection",
        description="Detects dynamic string formatting or concatenation in database query executions.",
        cwe_id="CWE-89",
        default_severity=Severity.HIGH,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        method_name = ""
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr

        if method_name in SQL_METHODS and node.args:
            first_arg = node.args[0]

            is_unsafe = False
            risk_desc = ""

            # 1. f-strings: cursor.execute(f"SELECT ... {val}")
            if isinstance(first_arg, ast.JoinedStr):
                # Inspect literal parts
                literal_parts = [
                    part.value for part in first_arg.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                ]
                full_literal = " ".join(literal_parts)
                if is_sql_string(full_literal):
                    is_unsafe = True
                    risk_desc = "F-string SQL query detected. Use parameterized queries (?, %s, or named placeholders) instead."

            # 2. % formatting or + concatenation: cursor.execute("SELECT ... %s" % val)
            elif isinstance(first_arg, ast.BinOp):
                if isinstance(first_arg.op, ast.Mod):
                    if isinstance(first_arg.left, ast.Constant) and isinstance(first_arg.left.value, str):
                        if is_sql_string(first_arg.left.value):
                            is_unsafe = True
                            risk_desc = "Percent-formatting string in SQL execute detected. Pass query arguments as a secondary tuple parameter."
                elif isinstance(first_arg.op, ast.Add):
                    # Concatenation with +
                    is_unsafe = True
                    risk_desc = "String concatenation with '+' in SQL execute detected. Use parameterized queries."

            # 3. .format() call: cursor.execute("SELECT ...".format(val))
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute):
                if first_arg.func.attr == "format" and isinstance(first_arg.func.value, ast.Constant):
                    if isinstance(first_arg.func.value.value, str) and is_sql_string(first_arg.func.value.value):
                        is_unsafe = True
                        risk_desc = "str.format() used in SQL query execution. Use parameterized queries."

            if is_unsafe:
                finding = self.create_finding(node, context, risk_desc, Severity.HIGH)
                if finding:
                    findings.append(finding)

        return findings
