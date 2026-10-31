"""
Command-line interface for AST-Sentinel.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List

from ast_sentinel import __version__
from ast_sentinel.auditor import CodeAuditor, AuditReport
from ast_sentinel.models import Finding, Severity
from ast_sentinel.rules import RULE_REGISTRY


# ANSI styling helpers
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"

SEVERITY_COLORS = {
    Severity.LOW: CYAN,
    Severity.MEDIUM: YELLOW,
    Severity.HIGH: RED,
    Severity.CRITICAL: MAGENTA,
}


def print_banner() -> None:
    banner = f"""{BOLD}{CYAN}
    ___   _____ ______      _____            __   _            __
   /   | / ___//_  __/     / ___/___  ____  / /_ (_)___  ___  / /
  / /| | \\__ \\  / / ______ \\__ \\/ _ \\/ __ \\/ __// / __ \\/ _ \\/ / 
 / ___ |___/ / / / /_____/___/ /  __/ / / / /_ / / / / /  __/ /  
/_/  |_/____/ /_/        /____/\\___/_/ /_/\\__//_/_/ /_/\\___/_/   
                                             v{__version__}{RESET}
    Lightweight AST-Driven Static Security Code Auditor
"""
    print(banner, file=sys.stderr)


def print_rules_catalog() -> None:
    """Lists all registered audit rules."""
    print(f"\n{BOLD}Registered Security Rules ({len(RULE_REGISTRY)}):{RESET}\n")
    print(f"{'ID':<8} {'CWE':<10} {'SEVERITY':<10} {'NAME':<28} {'DESCRIPTION'}")
    print("-" * 85)
    for rule_cls in RULE_REGISTRY:
        meta = rule_cls.metadata
        color = SEVERITY_COLORS.get(meta.default_severity, "")
        print(
            f"{BOLD}{meta.rule_id:<8}{RESET} "
            f"{meta.cwe_id:<10} "
            f"{color}{meta.default_severity.value:<10}{RESET} "
            f"{meta.name:<28} "
            f"{meta.description}"
        )
    print()


def render_human_report(report: AuditReport) -> None:
    """Renders findings in a human-friendly format."""
    if not report.findings:
        print(f"\n{BOLD}{GREEN}[✓] Clean codebase! No security issues detected.{RESET}")
        print(
            f"{DIM}Scanned {report.files_scanned} file(s) in {report.duration_seconds:.2f}s.{RESET}\n"
        )
        return

    print(
        f"\n{BOLD}{RED}[!] Audit complete: Found {len(report.findings)} potential issue(s) across {report.files_scanned} file(s) ({report.duration_seconds:.2f}s):{RESET}\n"
    )

    for idx, f in enumerate(report.findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "")
        print(
            f"{BOLD}{idx}. [{color}{f.severity.value}{RESET}{BOLD}] "
            f"[{CYAN}{f.rule_id}{RESET}{BOLD}] "
            f"[{f.cwe_id}] {f.rule_name}{RESET}"
        )
        print(f"   {DIM}File:{RESET} {f.file_path}:{f.line_number}:{f.col_offset}")
        print(f"   {DIM}Risk:{RESET} {f.message}")
        if f.snippet:
            print(f"   {DIM}Code:{RESET} {BOLD}{f.snippet}{RESET}")
        print()

    # Summary table
    counts = report.severity_counts
    print(f"{BOLD}Summary:{RESET} "
          f"{MAGENTA}CRITICAL: {counts[Severity.CRITICAL]}{RESET} | "
          f"{RED}HIGH: {counts[Severity.HIGH]}{RESET} | "
          f"{YELLOW}MEDIUM: {counts[Severity.MEDIUM]}{RESET} | "
          f"{CYAN}LOW: {counts[Severity.LOW]}{RESET}\n")


def render_json_report(report: AuditReport) -> None:
    payload = {
        "version": __version__,
        "summary": {
            "files_scanned": report.files_scanned,
            "duration_seconds": report.duration_seconds,
            "total_findings": len(report.findings),
            "severity_counts": {
                k.value: v for k, v in report.severity_counts.items()
            },
        },
        "findings": [asdict(f) for f in report.findings],
        "errors": report.errors,
    }
    print(json.dumps(payload, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ast-sentinel",
        description="AST-Sentinel: Static Security Code Auditor for Python Codebases.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to Python source file or repository root to audit (default: current directory).",
    )
    parser.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default=Severity.LOW.value,
        help="Minimum severity threshold to report (default: LOW).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: text (colored CLI) or json (machine readable).",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List all active security rules and exit.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 on ANY finding, not just HIGH/CRITICAL.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    if args.list_rules:
        print_rules_catalog()
        sys.exit(0)

    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    if args.format == "text":
        print_banner()

    min_severity = Severity(args.severity)
    auditor = CodeAuditor(min_severity=min_severity)
    report = auditor.audit_path(target_path)

    if args.format == "json":
        render_json_report(report)
    else:
        render_human_report(report)

    # Determine exit code for CI/CD gates
    if args.strict and len(report.findings) > 0:
        sys.exit(1)
    elif report.has_high_or_critical:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
