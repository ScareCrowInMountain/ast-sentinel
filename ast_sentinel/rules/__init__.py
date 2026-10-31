"""
Rules catalog initialization.
"""

from ast_sentinel.rules.base import RULE_REGISTRY, BaseRule
from ast_sentinel.rules.code_exec import ArbitraryCodeExecRule
from ast_sentinel.rules.command_injection import SubprocessShellRule
from ast_sentinel.rules.weak_crypto import InsecureHashRule
from ast_sentinel.rules.deserialization import InsecureDeserializationRule
from ast_sentinel.rules.insecure_temp import InsecureTempFileRule

__all__ = [
    "RULE_REGISTRY",
    "BaseRule",
    "ArbitraryCodeExecRule",
    "SubprocessShellRule",
    "InsecureHashRule",
    "InsecureDeserializationRule",
    "InsecureTempFileRule",
]
