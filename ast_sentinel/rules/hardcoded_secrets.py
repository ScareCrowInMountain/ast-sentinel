"""
SEC006: Hardcoded Secret / Credential Detection.
Detects potential hardcoded API keys, passwords, and access tokens in source code.
"""

from __future__ import annotations

import ast
import re
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


SUSPICIOUS_VAR_NAMES = {
    "api_key",
    "apikey",
    "secret_key",
    "secretkey",
    "access_token",
    "auth_token",
    "private_key",
    "aws_secret_access_key",
    "password",
    "passwd",
    "client_secret",
}

KNOWN_TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS Access Key ID
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),  # GitHub Personal Access Token
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),   # Slack Token
]

PLACEHOLDER_WORDS = {"test", "dummy", "placeholder", "example", "changeme", "default", "none", "null", ""}


@register_rule
class HardcodedSecretRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC006",
        name="Hardcoded Secret Detection",
        description="Detects potential hardcoded credentials, API keys, and sensitive tokens.",
        cwe_id="CWE-798",
        default_severity=Severity.HIGH,
    )

    def check_assign(
        self,
        node: ast.Assign,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Target names check
        target_names: List[str] = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_names.append(target.id.lower())

        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return findings

        secret_value = node.value.value.strip()

        # Check known regex token patterns directly
        for pattern in KNOWN_TOKEN_PATTERNS:
            if pattern.search(secret_value):
                finding = self.create_finding(
                    node,
                    context,
                    "High-confidence credential pattern detected in string literal. Move secrets to environment variables.",
                    Severity.CRITICAL,
                )
                if finding:
                    findings.append(finding)
                return findings

        # Check suspicious variable names
        for name in target_names:
            if any(suspicious in name for suspicious in SUSPICIOUS_VAR_NAMES):
                # Filter out obvious placeholders
                if len(secret_value) >= 8 and secret_value.lower() not in PLACEHOLDER_WORDS:
                    finding = self.create_finding(
                        node,
                        context,
                        f"Potential hardcoded secret assigned to '{name}'. Secrets should be loaded from secure vaults or env vars.",
                        Severity.HIGH,
                    )
                    if finding:
                        findings.append(finding)
                break

        return findings
