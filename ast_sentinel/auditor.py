"""
Auditor core: AST traversal and rule execution engine with context tracking.
"""

from __future__ import annotations

import ast
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from ast_sentinel.config import SentinelConfig
from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, Severity
from ast_sentinel.rules import RULE_REGISTRY, BaseRule


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, context: AnalysisContext, rules: List[BaseRule]):
        self.context = context
        self.rules = rules
        self.findings: List[Finding] = []

    def visit_Import(self, node: ast.Import) -> None:
        self.context.register_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.context.register_import_from(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for rule in self.rules:
            detected = rule.check_call(node, self.context)
            if detected:
                self.findings.extend(detected)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for rule in self.rules:
            detected = rule.check_assign(node, self.context)
            if detected:
                self.findings.extend(detected)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        for rule in self.rules:
            detected = rule.check_assert(node, self.context)
            if detected:
                self.findings.extend(detected)
        self.generic_visit(node)


@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> Dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def has_high_or_critical(self) -> bool:
        return any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in self.findings
        )


class CodeAuditor:
    """
    Main SAST engine that walks files, parses abstract syntax trees,
    and runs configured security rules with semantic context.
    """

    DEFAULT_IGNORE_DIRS: Set[str] = {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        "node_modules",
    }

    def __init__(
        self,
        min_severity: Severity = Severity.LOW,
        ignore_dirs: Optional[Set[str]] = None,
        ignore_rules: Optional[Set[str]] = None,
        config: Optional[SentinelConfig] = None,
    ):
        if config:
            self.min_severity = config.min_severity if min_severity == Severity.LOW else min_severity
            self.ignore_rules = {r.upper() for r in config.ignore_rules}
            self.ignore_dirs = set(self.DEFAULT_IGNORE_DIRS).union(config.ignore_paths)
        else:
            self.min_severity = min_severity
            self.ignore_rules = {r.upper() for r in (ignore_rules or set())}
            self.ignore_dirs = ignore_dirs if ignore_dirs is not None else set(self.DEFAULT_IGNORE_DIRS)

        # Initialize active rules, filtering out ignored rules
        self.rules: List[BaseRule] = [
            rule_cls() for rule_cls in RULE_REGISTRY
            if rule_cls.metadata.rule_id.upper() not in self.ignore_rules
        ]

    def audit_file(self, file_path: Path) -> List[Finding]:
        """Audits a single Python file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            source_lines = content.splitlines()

            context = AnalysisContext(str(file_path), source_lines)
            tree = ast.parse(content, filename=str(file_path))

            visitor = _ASTVisitor(context, self.rules)
            visitor.visit(tree)

            # Filter by severity and ignore rules
            threshold = self.min_severity.level
            return [
                f for f in visitor.findings
                if f.severity.level >= threshold and f.rule_id.upper() not in self.ignore_rules
            ]

        except SyntaxError as e:
            return [
                Finding(
                    rule_id="SYNTAX_ERR",
                    rule_name="Syntax Error",
                    cwe_id="CWE-Other",
                    severity=Severity.LOW,
                    message=f"Syntax error parsing file: {e.msg}",
                    file_path=str(file_path),
                    line_number=e.lineno or 0,
                    col_offset=e.offset or 0,
                )
            ]
        except Exception as e:
            return [
                Finding(
                    rule_id="SCAN_ERR",
                    rule_name="Scanner Exception",
                    cwe_id="CWE-Other",
                    severity=Severity.LOW,
                    message=f"Failed to scan file: {str(e)}",
                    file_path=str(file_path),
                    line_number=0,
                    col_offset=0,
                )
            ]

    def audit_path(self, target: Path) -> AuditReport:
        """Audits a file or recursively audits a directory."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        files_scanned = 0
        errors: List[str] = []

        if not target.exists():
            errors.append(f"Target path does not exist: {target}")
            return AuditReport(findings=[], files_scanned=0, duration_seconds=0.0, errors=errors)

        if target.is_file():
            if target.suffix == ".py":
                files_scanned += 1
                findings.extend(self.audit_file(target))
        elif target.is_dir():
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
                for file in files:
                    if file.endswith(".py"):
                        file_path = Path(root) / file
                        files_scanned += 1
                        findings.extend(self.audit_file(file_path))

        duration = time.perf_counter() - start_time
        return AuditReport(
            findings=findings,
            files_scanned=files_scanned,
            duration_seconds=round(duration, 4),
            errors=errors,
        )
