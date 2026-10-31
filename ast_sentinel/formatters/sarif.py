"""
OASIS SARIF (Static Analysis Results Interchange Format) v2.1.0 exporter.
Enables native integration with GitHub Code Scanning alerts.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ast_sentinel import __version__
from ast_sentinel.auditor import AuditReport
from ast_sentinel.models import Finding, Severity
from ast_sentinel.rules import RULE_REGISTRY


SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def generate_sarif_report(report: AuditReport, repo_root: str = "") -> Dict[str, Any]:
    """Generates a complete SARIF v2.1.0 JSON payload from an AuditReport."""
    rules_catalog: List[Dict[str, Any]] = []

    for rule_cls in RULE_REGISTRY:
        meta = rule_cls.metadata
        rules_catalog.append({
            "id": meta.rule_id,
            "name": meta.name.replace(" ", ""),
            "shortDescription": {"text": meta.name},
            "fullDescription": {"text": meta.description},
            "defaultConfiguration": {
                "level": SARIF_SEVERITY_MAP.get(meta.default_severity, "warning")
            },
            "helpUri": f"https://cwe.mitre.org/data/definitions/{meta.cwe_id.replace('CWE-', '')}.html"
            if meta.cwe_id.startswith("CWE-") and meta.cwe_id != "CWE-Other"
            else "https://github.com/ScareCrowInMountain/ast-sentinel",
            "properties": {
                "tags": ["security", meta.cwe_id],
                "precision": "high",
            },
        })

    results: List[Dict[str, Any]] = []
    for f in report.findings:
        file_uri = f.file_path
        if repo_root and file_uri.startswith(repo_root):
            file_uri = file_uri[len(repo_root):].lstrip("/\\")

        result_entry: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": SARIF_SEVERITY_MAP.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, f.line_number),
                            "startColumn": max(1, f.col_offset + 1),
                        },
                    }
                }
            ],
        }
        if f.snippet:
            result_entry["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet
            }
        results.append(result_entry)

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AST-Sentinel",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/ScareCrowInMountain/ast-sentinel",
                        "rules": rules_catalog,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif_doc
