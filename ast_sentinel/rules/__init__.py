"""
Rules catalog initialization.
"""

from ast_sentinel.rules.base import RULE_REGISTRY, BaseRule
from ast_sentinel.rules.code_exec import ArbitraryCodeExecRule
from ast_sentinel.rules.command_injection import SubprocessShellRule
from ast_sentinel.rules.weak_crypto import InsecureHashRule
from ast_sentinel.rules.deserialization import InsecureDeserializationRule
from ast_sentinel.rules.insecure_temp import InsecureTempFileRule
from ast_sentinel.rules.hardcoded_secrets import HardcodedSecretRule
from ast_sentinel.rules.sql_injection import SqlInjectionRule
from ast_sentinel.rules.xxe_xml import XxeXmlRule
from ast_sentinel.rules.bind_all_interfaces import BindAllInterfacesRule
from ast_sentinel.rules.ssl_verification import SslVerificationRule
from ast_sentinel.rules.weak_random import WeakRandomRule
from ast_sentinel.rules.assert_usage import AssertUsageRule
from ast_sentinel.rules.archive_slip import ArchiveSlipRule
from ast_sentinel.rules.debug_mode import DebugModeRule
from ast_sentinel.rules.path_traversal import PathTraversalRule

__all__ = [
    "RULE_REGISTRY",
    "BaseRule",
    "ArbitraryCodeExecRule",
    "SubprocessShellRule",
    "InsecureHashRule",
    "InsecureDeserializationRule",
    "InsecureTempFileRule",
    "HardcodedSecretRule",
    "SqlInjectionRule",
    "XxeXmlRule",
    "BindAllInterfacesRule",
    "SslVerificationRule",
    "WeakRandomRule",
    "AssertUsageRule",
    "ArchiveSlipRule",
    "DebugModeRule",
    "PathTraversalRule",
]
