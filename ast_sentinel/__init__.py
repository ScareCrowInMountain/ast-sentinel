"""
AST-Sentinel: Static Code Security Auditor using Python Abstract Syntax Trees.
"""

from ast_sentinel.auditor import CodeAuditor
from ast_sentinel.config import SentinelConfig
from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity

__version__ = "0.2.0"
__all__ = [
    "AnalysisContext",
    "CodeAuditor",
    "Finding",
    "RuleMetadata",
    "SentinelConfig",
    "Severity",
]
