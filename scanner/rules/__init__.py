"""
MCP Sentinel Mesh Rules Package
"""

from scanner.rules.base import BaseRule
from scanner.rules.rules_impl import (
    ALL_RULES,
    RuleSuspiciousDescription,
    RuleHiddenSideEffects,
    RuleShellExecution,
    RuleFileSystemAccess,
    RuleNetworkEgress,
    RuleCredentialExposure,
    RuleMissingInputConstraints,
    RuleBroadWildcardSelectors,
    RuleToolNamingDeception,
    RuleConflictingPermissions,
    RuleMissingAuthentication,
    RuleMissingOutputSensitivity,
)

__all__ = [
    "BaseRule",
    "ALL_RULES",
    "RuleSuspiciousDescription",
    "RuleHiddenSideEffects",
    "RuleShellExecution",
    "RuleFileSystemAccess",
    "RuleNetworkEgress",
    "RuleCredentialExposure",
    "RuleMissingInputConstraints",
    "RuleBroadWildcardSelectors",
    "RuleToolNamingDeception",
    "RuleConflictingPermissions",
    "RuleMissingAuthentication",
    "RuleMissingOutputSensitivity",
]
