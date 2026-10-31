"""
Base classes and registry for security audit rules.
"""

from __future__ import annotations

import ast
from abc import ABC
from typing import List, Optional, Type

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity


class BaseRule(ABC):
    """Abstract base class for all AST-based security detection rules."""

    metadata: RuleMetadata

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        """Inspects ast.Call nodes."""
        return []

    def check_assign(
        self,
        node: ast.Assign,
        context: AnalysisContext,
    ) -> List[Finding]:
        """Inspects ast.Assign nodes (e.g., hardcoded secrets, debug flags)."""
        return []

    def check_assert(
        self,
        node: ast.Assert,
        context: AnalysisContext,
    ) -> List[Finding]:
        """Inspects ast.Assert nodes."""
        return []

    def create_finding(
        self,
        node: ast.AST,
        context: AnalysisContext,
        message: str,
        severity: Optional[Severity] = None,
    ) -> Optional[Finding]:
        """
        Creates a structured Finding object from an AST node.
        Returns None if the finding is suppressed via inline comments (# nosec).
        """
        lineno = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)

        # Check for inline suppression directives (# nosec)
        if context.is_suppressed(self.metadata.rule_id, lineno):
            return None

        snippet = None
        if 1 <= lineno <= len(context.source_lines):
            snippet = context.source_lines[lineno - 1].strip()

        return Finding(
            rule_id=self.metadata.rule_id,
            rule_name=self.metadata.name,
            cwe_id=self.metadata.cwe_id,
            severity=severity or self.metadata.default_severity,
            message=message,
            file_path=context.file_path,
            line_number=lineno,
            col_offset=col_offset,
            snippet=snippet,
        )


RULE_REGISTRY: List[Type[BaseRule]] = []


def register_rule(cls: Type[BaseRule]) -> Type[BaseRule]:
    """Decorator to register a rule into the active rule catalog."""
    if cls not in RULE_REGISTRY:
        RULE_REGISTRY.append(cls)
    return cls
