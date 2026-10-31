"""
AST-Sentinel: Static Code Security Auditor using Python Abstract Syntax Trees.
"""

from ast_sentinel.auditor import CodeAuditor
from ast_sentinel.models import Finding, RuleMetadata, Severity

__version__ = "0.1.0"
__all__ = ["CodeAuditor", "Finding", "RuleMetadata", "Severity"]
