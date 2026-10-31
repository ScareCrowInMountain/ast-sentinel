"""
Command-line interface for AST-Sentinel.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from ast_sentinel import __version__
from ast_sentinel.auditor import AuditReport, CodeAuditor
from ast_sentinel.config import SentinelConfig
from ast_sentinel.formatters.sarif import generate_sarif_report
from ast_sentinel.models import Severity
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
    print(f"{'ID':<8} {'CWE':<10} {'SEVERITY':<10} {'NAME':<32} {'DESCRIPTION'}")
    print("-" * 95)
    for rule_cls in RULE_REGISTRY:
        meta = rule_cls.metadata
        color = SEVERITY_COLORS.get(meta.default_severity, "")
        print(
            f"{BOLD}{meta.rule_id:<8}{RESET} "
            f"{meta.cwe_id:<10} "
            f"{color}{meta.default_severity.value:<10}{RESET} "
            f"{meta.name:<32} "
            f"{meta.description}"
        )
    print()


def render_human_report(report: AuditReport) -> str:
    """Renders findings in a human-friendly format."""
    lines = []
    if not report.findings:
        lines.append(f"\n{BOLD}{GREEN}[✓] Clean codebase! No security issues detected.{RESET}")
        lines.append(
            f"{DIM}Scanned {report.files_scanned} file(s) in {report.duration_seconds:.2f}s.{RESET}\n"
        )
        return "\n".join(lines)

    lines.append(
        f"\n{BOLD}{RED}[!] Audit complete: Found {len(report.findings)} potential issue(s) across {report.files_scanned} file(s) ({report.duration_seconds:.2f}s):{RESET}\n"
    )

    for idx, f in enumerate(report.findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "")
        lines.append(
            f"{BOLD}{idx}. [{color}{f.severity.value}{RESET}{BOLD}] "
            f"[{CYAN}{f.rule_id}{RESET}{BOLD}] "
            f"[{f.cwe_id}] {f.rule_name}{RESET}"
        )
        lines.append(f"   {DIM}File:{RESET} {f.file_path}:{f.line_number}:{f.col_offset}")
        lines.append(f"   {DIM}Risk:{RESET} {f.message}")
        if f.snippet:
            lines.append(f"   {DIM}Code:{RESET} {BOLD}{f.snippet}{RESET}")
        lines.append("")

    counts = report.severity_counts
    lines.append(f"{BOLD}Summary:{RESET} "
                 f"{MAGENTA}CRITICAL: {counts[Severity.CRITICAL]}{RESET} | "
                 f"{RED}HIGH: {counts[Severity.HIGH]}{RESET} | "
                 f"{YELLOW}MEDIUM: {counts[Severity.MEDIUM]}{RESET} | "
                 f"{CYAN}LOW: {counts[Severity.LOW]}{RESET}\n")

    return "\n".join(lines)


def render_json_report(report: AuditReport) -> str:
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
    return json.dumps(payload, indent=2)


def render_sarif_report_str(report: AuditReport, target_path: Path) -> str:
    repo_root = str(target_path.resolve()) if target_path.is_dir() else str(target_path.parent.resolve())
    doc = generate_sarif_report(report, repo_root=repo_root)
    return json.dumps(doc, indent=2)


def write_or_print(content: str, output_path: Optional[Path]) -> None:
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"{GREEN}[✓] Report saved to {output_path}{RESET}", file=sys.stderr)
    else:
        print(content)


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
        default=None,
        help="Minimum severity threshold to report (default: LOW or from config).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format: text (colored CLI), json, or sarif (OASIS v2.1.0 for GitHub Code Scanning).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write report output to specified file path instead of stdout.",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        help="Path to custom configuration file (sentinel.toml or pyproject.toml).",
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        help="Rule ID to ignore (can be specified multiple times, e.g. --ignore-rule SEC012).",
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

    if args.format == "text" and not args.output:
        print_banner()

    # Load configuration
    config = SentinelConfig.load(config_path=args.config, project_root=target_path if target_path.is_dir() else target_path.parent)

    # CLI args override config
    min_sev = Severity(args.severity) if args.severity else config.min_severity
    cli_ignored = {r.upper() for r in args.ignore_rule}
    all_ignored = config.ignore_rules.union(cli_ignored)
    is_strict = args.strict or config.strict

    auditor = CodeAuditor(min_severity=min_sev, ignore_rules=all_ignored, config=config)
    report = auditor.audit_path(target_path)

    # Format output
    if args.format == "json":
        output_str = render_json_report(report)
    elif args.format == "sarif":
        output_str = render_sarif_report_str(report, target_path)
    else:
        output_str = render_human_report(report)

    write_or_print(output_str, args.output)

    # Exit code determination
    if is_strict and len(report.findings) > 0:
        sys.exit(1)
    elif report.has_high_or_critical:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
