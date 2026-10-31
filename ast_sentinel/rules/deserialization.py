"""
SEC004: Insecure Deserialization Detection.
Detects unauthenticated deserialization using pickle or PyYAML without SafeLoader.
"""

from __future__ import annotations

import ast
from typing import List

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
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            mod = node.func.value.id
            method = node.func.attr

            # 1. pickle.load / pickle.loads / _pickle.loads
            if mod in ("pickle", "_pickle", "cPickle") and method in ("load", "loads"):
                findings.append(
                    self.create_finding(
                        node,
                        file_path,
                        source_lines,
                        f"Unsafe deserialization with '{mod}.{method}()' can lead to arbitrary code execution if input is untrusted.",
                        Severity.HIGH,
                    )
                )

            # 2. yaml.load without SafeLoader
            elif mod == "yaml" and method == "load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        # Check Loader=yaml.SafeLoader or Loader=SafeLoader
                        loader_dump = ast.dump(kw.value)
                        if "SafeLoader" in loader_dump or "CSafeLoader" in loader_dump:
                            has_safe_loader = True
                            break

                if not has_safe_loader:
                    findings.append(
                        self.create_finding(
                            node,
                            file_path,
                            source_lines,
                            "yaml.load() without SafeLoader is vulnerable to arbitrary code execution. Use yaml.safe_load() instead.",
                            Severity.HIGH,
                        )
                    )

        return findings
