"""
SEC009: Binding to All Interfaces (0.0.0.0) Detection.
Detects server applications or sockets bound to all available network interfaces.
"""

from __future__ import annotations

import ast
from typing import List

from ast_sentinel.context import AnalysisContext
from ast_sentinel.models import Finding, RuleMetadata, Severity
from ast_sentinel.rules.base import BaseRule, register_rule


ALL_INTERFACES = {"0.0.0.0", "::"}


@register_rule
class BindAllInterfacesRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="SEC009",
        name="Binding to All Interfaces",
        description="Detects binding to 0.0.0.0 or ::, exposing services to the public network.",
        cwe_id="CWE-200",
        default_severity=Severity.MEDIUM,
    )

    def check_call(
        self,
        node: ast.Call,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        mod, func = context.resolve_call(node.func)

        is_violating = False

        # 1. socket.bind(('0.0.0.0', port))
        if func == "bind" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.Tuple, ast.List)) and first_arg.elts:
                host_elt = first_arg.elts[0]
                if isinstance(host_elt, ast.Constant) and host_elt.value in ALL_INTERFACES:
                    is_violating = True

        # 2. app.run(host='0.0.0.0')
        if func == "run":
            for kw in node.keywords:
                if kw.arg == "host" and isinstance(kw.value, ast.Constant):
                    if kw.value.value in ALL_INTERFACES:
                        is_violating = True

        if is_violating:
            finding = self.create_finding(
                node,
                context,
                "Binding service to '0.0.0.0' exposes the endpoint to all network interfaces. Bind to '127.0.0.1' unless explicitly intended for external access.",
                Severity.MEDIUM,
            )
            if finding:
                findings.append(finding)

        return findings
