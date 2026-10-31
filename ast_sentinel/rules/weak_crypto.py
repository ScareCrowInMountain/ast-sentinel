"""
SEC003: Insecure Cryptographic Hash Detection.
Detects usage of broken or collision-vulnerable hash functions (MD5, SHA1).
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class InsecureHashRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC003",
        name="Weak Cryptographic Hash",
        description="Detects MD5 or SHA1 hash usage without usedforsecurity=False flag.",
        cwe_id="CWE-327",
        default_severity=Severity.MEDIUM,
    )

    WEAK_HASHES = {"md5", "sha1"}

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        algo_name = ""
        is_hashlib_call = False

        if mod == "hashlib":
            if func in self.WEAK_HASHES:
                algo_name = func
                is_hashlib_call = True
            elif func == "new" and node.args and isinstance(node.args[0], ast.Constant):
                arg_val = str(node.args[0].value).lower()
                if arg_val in self.WEAK_HASHES:
                    algo_name = arg_val
                    is_hashlib_call = True

        if is_hashlib_call:
            is_defended = any(
                kw.arg == "usedforsecurity"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords
            )
            if not is_defended:
                finding = self.create_finding(
                    node,
                    context,
                    f"Insecure hash '{algo_name.upper()}' detected. Use SHA256/SHA512 for security contexts, or set usedforsecurity=False for non-security checksums.",
                    Severity.MEDIUM,
                )
                if finding:
                    findings.append(finding)

        return findings
