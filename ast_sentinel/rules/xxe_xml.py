"""
SEC008: XML External Entity (XXE) Detection.
Detects usage of standard vulnerable XML parsers without safe configuration.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


UNSAFE_XML_MODULES = {
    "xml.etree.ElementTree",
    "xml.dom.minidom",
    "xml.dom.pulldom",
    "xml.sax",
    "lxml.etree",
}


@register_rule
class XxeXmlRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC008",
        name="XML External Entity (XXE)",
        description="Detects parsing of XML data using standard libraries susceptible to XXE attacks.",
        cwe_id="CWE-611",
        default_severity=Severity.MEDIUM,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        if mod in UNSAFE_XML_MODULES and func in ("parse", "fromstring", "parseString", "XML"):
            finding = self.create_finding(
                node,
                context,
                f"Standard XML parser '{mod}.{func}()' is susceptible to XXE and entity expansion DoS attacks. Use 'defusedxml' equivalents.",
                Severity.MEDIUM,
            )
            if finding:
                findings.append(finding)

        return findings
