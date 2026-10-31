"""
SEC010: Disabled SSL/TLS Verification Detection.
Detects requests or SSL contexts where certificate verification is disabled.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


REQUEST_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}


@register_rule
class SslVerificationRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC010",
        name="Disabled SSL Verification",
        description="Detects disabled SSL/TLS certificate verification (verify=False or unverified SSL contexts).",
        cwe_id="CWE-295",
        default_severity=Severity.HIGH,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        # 1. requests / httpx with verify=False
        if func in REQUEST_METHODS:
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant):
                    if kw.value.value is False:
                        finding = self.create_finding(
                            node,
                            context,
                            f"HTTP request '{func}()' with verify=False disables TLS validation, making connection vulnerable to Man-in-the-Middle (MitM) attacks.",
                            Severity.HIGH,
                        )
                        if finding:
                            findings.append(finding)

        # 2. ssl._create_unverified_context()
        if mod == "ssl" and func == "_create_unverified_context":
            finding = self.create_finding(
                node,
                context,
                "Explicit creation of unverified SSL context bypasses peer certificate validation. Use ssl.create_default_context().",
                Severity.HIGH,
            )
            if finding:
                findings.append(finding)

        return findings
