"""
MCP Sentinel Mesh - Adversarial Test Engine Base
Contracts and base abstractions for adversarial evaluation test vectors.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class AdversarialResult(BaseModel):
    test_id: str
    category: str
    name: str
    passed: bool
    detected: bool
    blocked: bool
    severity: str
    execution_time_ms: float
    request_payload: Dict[str, Any]
    response_payload: Optional[Dict[str, Any]] = None
    violation_details: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AdversarialTestCase(BaseModel):
    test_id: str
    category: str
    name: str
    description: str
    target_tool: str
    target_server: str
    payload: Dict[str, Any]
    expected_outcome: str = "BLOCKED"  # BLOCKED | REDACTED | DETECTED
    attack_vector: str
    remediation_hint: str
