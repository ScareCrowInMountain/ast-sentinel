"""
AST-Sentinel: Static Code Security Auditor using Python Abstract Syntax Trees.
"""

from ast_sentinel.models import Finding, Severity, RuleMetadata
from ast_sentinel.auditor import CodeAuditor

__version__ = "0.1.0"
__all__ = ["CodeAuditor", "Finding", "Severity", "RuleMetadata"]
