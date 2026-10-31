"""
SEC011: Cryptographically Weak Randomness Detection.
Detects standard pseudo-random number generator (PRNG) usage for security-sensitive tokens.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


WEAK_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample"}


@register_rule
class WeakRandomRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC011",
        name="Weak Randomness",
        description="Detects pseudo-random number generator (PRNG) calls in security-sensitive contexts.",
        cwe_id="CWE-338",
        default_severity=Severity.MEDIUM,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        if mod == "random" and func in WEAK_RANDOM_FUNCS:
            lineno = getattr(node, "lineno", 0)
            line_str = context.source_lines[lineno - 1].lower() if 1 <= lineno <= len(context.source_lines) else ""

            # Check if line contains security keywords
            security_keywords = {"token", "key", "password", "secret", "salt", "session", "nonce", "auth"}
            if any(k in line_str for k in security_keywords):
                finding = self.create_finding(
                    node,
                    context,
                    f"Standard pseudo-random generator 'random.{func}()' used in security-sensitive context. Use the 'secrets' module instead.",
                    Severity.MEDIUM,
                )
                if finding:
                    findings.append(finding)

        return findings
