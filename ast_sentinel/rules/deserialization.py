"""
SEC004: Insecure Deserialization Detection.
Detects unauthenticated deserialization using pickle or PyYAML without SafeLoader.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


@register_rule
class InsecureDeserializationRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC004",
        name="Insecure Deserialization",
        description="Detects pickle deserialization or yaml.load without SafeLoader.",
        cwe_id="CWE-502",
        default_severity=Severity.HIGH,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        # 1. pickle.load / pickle.loads / _pickle.loads / marshal / shelve
        if mod in ("pickle", "_pickle", "cPickle", "marshal") and func in ("load", "loads"):
            finding = self.create_finding(
                node,
                context,
                f"Unsafe deserialization with '{mod}.{func}()' can lead to arbitrary code execution if input is untrusted.",
                Severity.HIGH,
            )
            if finding:
                findings.append(finding)

        # 2. yaml.load without SafeLoader
        elif mod == "yaml" and func == "load":
            has_safe_loader = any(
                kw.arg == "Loader" and ("SafeLoader" in ast.dump(kw.value) or "CSafeLoader" in ast.dump(kw.value))
                for kw in node.keywords
            )
            if not has_safe_loader:
                finding = self.create_finding(
                    node,
                    context,
                    "yaml.load() without SafeLoader is vulnerable to arbitrary code execution. Use yaml.safe_load() instead.",
                    Severity.HIGH,
                )
                if finding:
                    findings.append(finding)

        return findings
