"""
Data models and core definitions for AST-Sentinel.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        levels = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return levels[self]


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    name: str
    description: str
    cwe_id: str
    default_severity: Severity


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    cwe_id: str
    severity: Severity
    message: str
    file_path: str
    line_number: int
    col_offset: int
    snippet: Optional[str] = None
