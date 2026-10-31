"""
Base classes and registry for security audit rules.
"""

from __future__ import annotations

import ast
from abc import ABC
from typing import List, Optional, Type

from ast_sentinel.models import Finding, RuleMetadata, Severity


class BaseRule(ABC):
    """Abstract base class for all AST-based security detection rules."""

    metadata: RuleMetadata

    def check_call(
        self,
        node: ast.Call,
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        """Inspects ast.Call nodes. Override in subclass to implement checks."""
        return []

    def create_finding(
        self,
        node: ast.AST,
        file_path: str,
        source_lines: List[str],
        message: str,
        severity: Optional[Severity] = None,
    ) -> Finding:
        """Helper to create a structured Finding object from an AST node."""
        lineno = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)
        snippet = None
        if 1 <= lineno <= len(source_lines):
            snippet = source_lines[lineno - 1].strip()

        return Finding(
            rule_id=self.metadata.rule_id,
            rule_name=self.metadata.name,
            cwe_id=self.metadata.cwe_id,
            severity=severity or self.metadata.default_severity,
            message=message,
            file_path=file_path,
            line_number=lineno,
            col_offset=col_offset,
            snippet=snippet,
        )


RULE_REGISTRY: List[Type[BaseRule]] = []


def register_rule(cls: Type[BaseRule]) -> Type[BaseRule]:
    """Decorator to register a rule into the active rule catalog."""
    RULE_REGISTRY.append(cls)
    return cls
