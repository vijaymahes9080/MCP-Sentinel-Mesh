"""
MCP Sentinel Mesh - Rule Engine Base
Abstract base class and registry for deterministic security rules.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from backend.schemas.contracts import SecurityFinding, ToolDefinition, Severity, Confidence


class BaseRule(ABC):
    rule_id: str
    title: str
    severity: Severity
    default_confidence: Confidence
    description: str
    remediation: str
    references: List[str]
    false_positive_guidance: str

    @abstractmethod
    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        """Evaluate a single tool definition and return any security findings."""
        pass

    def create_finding(
        self,
        tool: ToolDefinition,
        evidence: str,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        custom_remediation: Optional[str] = None
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity or self.severity,
            confidence=confidence or self.default_confidence,
            affected_target=tool.name,
            evidence=evidence[:4000],
            remediation=custom_remediation or self.remediation,
            references=self.references,
            false_positive_guidance=self.false_positive_guidance
        )
