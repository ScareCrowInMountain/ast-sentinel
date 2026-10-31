"""
SEC003: Insecure Cryptographic Hash Detection.
Detects usage of broken or collision-vulnerable hash functions (MD5, SHA1).
"""

from __future__ import annotations

import ast
from typing import List

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
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        algo_name = ""
        is_hashlib_call = False

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in self.WEAK_HASHES:
                    algo_name = node.func.attr
                    is_hashlib_call = True
                elif node.func.attr == "new":
                    # Check hashlib.new("md5")
                    if node.args and isinstance(node.args[0], ast.Constant):
                        if str(node.args[0].value).lower() in self.WEAK_HASHES:
                            algo_name = str(node.args[0].value).lower()
                            is_hashlib_call = True

        if is_hashlib_call:
            # Check if usedforsecurity=False is set
            is_defended = any(
                kw.arg == "usedforsecurity"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords
            )
            if not is_defended:
                findings.append(
                    self.create_finding(
                        node,
                        file_path,
                        source_lines,
                        f"Insecure hash '{algo_name.upper()}' detected. Use SHA256/SHA512 for security contexts, or set usedforsecurity=False for non-security checksums.",
                        Severity.MEDIUM,
                    )
                )

        return findings
