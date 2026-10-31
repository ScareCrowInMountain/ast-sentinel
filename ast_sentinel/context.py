"""
Context tracking: Scope, import aliases, and inline comment suppressions.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple


# Regex pattern to match inline suppression comments:
# Examples:
#   # nosec
#   # nosec: SEC001, SEC002
#   # ast-sentinel: ignore=SEC001,SEC003
#   # sentinel: disable=SEC002
SUPPRESSION_REGEX = re.compile(
    r"#\s*(?:nosec(?::\s*([A-Za-z0-9_,\s]+))?|(?:ast-)?sentinel:\s*(?:ignore|disable)=([A-Za-z0-9_,\s]+))",
    re.IGNORECASE,
)


class AnalysisContext:
    """
    Holds lexical and semantic context for a single Python source file.
    Tracks imports, aliasing, and line-level suppression directives.
    """

    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines

        # Maps local variable/function name -> (module_path, original_symbol)
        # e.g., 'sp' -> ('subprocess', None)
        # e.g., 'sub_run' -> ('subprocess', 'run')
        self.aliases: Dict[str, Tuple[str, Optional[str]]] = {}

        # Maps 1-based line number -> set of suppressed rule IDs (or {'*'} for all)
        self.suppressions: Dict[int, Set[str]] = {}

        self._parse_suppression_comments()

    def _parse_suppression_comments(self) -> None:
        """Scans source lines for # nosec or # sentinel: ignore=... comments."""
        for lineno, line in enumerate(self.source_lines, 1):
            match = SUPPRESSION_REGEX.search(line)
            if match:
                rules_part = match.group(1) or match.group(2)
                if rules_part:
                    rule_ids = {
                        r.strip().upper() for r in rules_part.split(",") if r.strip()
                    }
                    self.suppressions[lineno] = rule_ids
                else:
                    # Generic '# nosec' without parameters suppresses everything on this line
                    self.suppressions[lineno] = {"*"}

    def is_suppressed(self, rule_id: str, lineno: int) -> bool:
        """Checks if a rule is suppressed on the given line."""
        if lineno not in self.suppressions:
            return False
        line_rules = self.suppressions[lineno]
        return "*" in line_rules or rule_id.upper() in line_rules

    def register_import(self, node: ast.Import) -> None:
        """Tracks 'import foo [as bar]' nodes."""
        for alias in node.names:
            local_name = alias.asname if alias.asname else alias.name
            self.aliases[local_name] = (alias.name, None)

    def register_import_from(self, node: ast.ImportFrom) -> None:
        """Tracks 'from foo import bar [as baz]' nodes."""
        module = node.module or ""
        for alias in node.names:
            local_name = alias.asname if alias.asname else alias.name
            self.aliases[local_name] = (module, alias.name)

    def resolve_call(self, func_node: ast.AST) -> Tuple[Optional[str], str]:
        """
        Resolves an AST Call func node to its canonical (module, function_name) tuple.
        Examples:
          eval(...)                  -> (None, 'eval')
          os.system(...)             -> ('os', 'system')
          sp.run(...) [import sp]    -> ('subprocess', 'run')
          my_run(...) [from sp run]  -> ('subprocess', 'run')
        """
        if isinstance(func_node, ast.Name):
            name = func_node.id
            if name in self.aliases:
                mod, sym = self.aliases[name]
                if sym is not None:
                    return mod, sym
                return mod, ""
            return None, name

        if isinstance(func_node, ast.Attribute):
            attr_name = func_node.attr
            if isinstance(func_node.value, ast.Name):
                obj_name = func_node.value.id
                if obj_name in self.aliases:
                    mod, _ = self.aliases[obj_name]
                    return mod, attr_name
                return obj_name, attr_name

        return None, ""
