"""
Configuration loader: Reads settings from sentinel.toml or pyproject.toml.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from ast_sentinel.models import Severity

# Attempt standard library tomllib (Python 3.11+) or tomli fallback
try:
    import tomllib  # type: ignore
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


@dataclass
class SentinelConfig:
    min_severity: Severity = Severity.LOW
    ignore_rules: Set[str] = field(default_factory=set)
    ignore_paths: Set[str] = field(default_factory=set)
    strict: bool = False

    @classmethod
    def load(cls, config_path: Optional[Path] = None, project_root: Optional[Path] = None) -> SentinelConfig:
        """Loads configuration from specified file or default locations."""
        if config_path and config_path.is_file():
            return cls._parse_file(config_path)

        root = project_root or Path.cwd()

        # Check sentinel.toml
        sentinel_toml = root / "sentinel.toml"
        if sentinel_toml.is_file():
            return cls._parse_file(sentinel_toml)

        # Check pyproject.toml
        pyproject_toml = root / "pyproject.toml"
        if pyproject_toml.is_file():
            return cls._parse_file(pyproject_toml, section="tool.ast-sentinel")

        return cls()

    @classmethod
    def _parse_file(cls, path: Path, section: Optional[str] = None) -> SentinelConfig:
        if tomllib is None:
            # TOML parser unavailable; return defaults
            return cls()

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)

            if section:
                for part in section.split("."):
                    if isinstance(data, dict) and part in data:
                        data = data[part]
                    else:
                        return cls()

            if not isinstance(data, dict):
                return cls()

            min_sev = Severity.LOW
            if "min_severity" in data:
                try:
                    min_sev = Severity(str(data["min_severity"]).upper())
                except ValueError:
                    pass

            ignore_rules = {str(r).upper() for r in data.get("ignore_rules", [])}
            ignore_paths = {str(p) for p in data.get("ignore_paths", [])}
            strict = bool(data.get("strict", False))

            return cls(
                min_severity=min_sev,
                ignore_rules=ignore_rules,
                ignore_paths=ignore_paths,
                strict=strict,
            )
        except Exception:
            return cls()
