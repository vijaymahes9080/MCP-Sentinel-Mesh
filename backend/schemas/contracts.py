"""
MCP Sentinel Mesh - Core Data Contracts and Schemas
Strictly validated Pydantic v2 data models for MCP tools, security findings, runtime policies, and audit logs.
"""

from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import uuid
from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    DETECTED = "DETECTED"


class PermissionScope(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    ADMIN = "admin"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ToolCallStatus(str, Enum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"
    ERROR = "error"


# 1. Tool Permission Contract
class ToolPermission(BaseModel):
    scope: PermissionScope = Field(..., description="Operational scope (read, write, execute, network, admin)")
    resource_patterns: List[str] = Field(default_factory=lambda: ["*"], description="Allowed resource URI or glob patterns")
    data_classification: DataClassification = Field(default=DataClassification.INTERNAL, description="Data sensitivity tier")
    is_destructive: bool = Field(default=False, description="Whether tool execution mutates or destroys state")

    @field_validator("resource_patterns")
    @classmethod
    def validate_patterns(cls, v: List[str]) -> List[str]:
        if not v:
            return ["*"]
        for p in v:
            if len(p) > 256:
                raise ValueError("Resource pattern too long (max 256 chars)")
        return v


# 2. Tool Definition Contract
class ToolDefinition(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Unique identifier for the tool")
    description: str = Field(..., min_length=1, max_length=4096, description="Human/LLM readable tool purpose")
    parameters_schema: Dict[str, Any] = Field(default_factory=dict, description="JSON Schema for tool arguments")
    return_schema: Optional[Dict[str, Any]] = Field(default=None, description="Optional JSON Schema for returned data")
    permissions: List[ToolPermission] = Field(default_factory=list, description="Declared explicit permissions")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Arbitrary security metadata annotations")
    source_version: str = Field(default="1.0.0", max_length=32, description="Tool / manifest semantic version")
    mcp_server_id: Optional[str] = Field(default=None, max_length=128, description="Parent MCP server identifier")

    @field_validator("name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        # Enforce alphanumeric, underscores, hyphens, colons
        import re
        if not re.match(r"^[a-zA-Z0-9_\-:]+$", v):
            raise ValueError(f"Invalid tool name characters in '{v}'")
        return v


# 3. Tool Call Contract
class ToolCall(BaseModel):
    call_id: str = Field(default_factory=lambda: f"call-{uuid.uuid4().hex[:12]}", description="Unique trace ID")
    correlation_id: str = Field(default_factory=lambda: f"corr-{uuid.uuid4().hex[:12]}", description="Session or distributed trace ID")
    caller_agent_id: str = Field(default="agent-default", max_length=128, description="ID of the initiating AI Agent")
    caller_user_id: Optional[str] = Field(default=None, max_length=128, description="End-user principal if present")
    tenant_id: str = Field(default="tenant-default", max_length=64, description="Multi-tenant boundary")
    tool_name: str = Field(..., min_length=1, max_length=128)
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool input arguments")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    signature: Optional[str] = Field(default=None, description="Optional HMAC or JWT signature of call")

    @field_validator("arguments")
    @classmethod
    def validate_args_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        import json
        serialized = json.dumps(v)
        if len(serialized) > 1_000_000:  # 1MB limit on arguments
            raise ValueError("Tool arguments payload exceeds maximum limit of 1MB")
        return v


# 4. Tool Response Contract
class ToolResponse(BaseModel):
    call_id: str
    status: ToolCallStatus
    result: Optional[Any] = None
    sanitized_result: Optional[Any] = None
    redaction_applied: bool = False
    redactions_count: int = 0
    blocked_reason: Optional[str] = None
    execution_time_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# 5. Security Finding Contract
class SecurityFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    rule_id: str = Field(..., max_length=64, description="Standard rule code e.g. SEC-MCP-001")
    title: str = Field(..., max_length=256)
    severity: Severity
    confidence: Confidence
    affected_target: str = Field(..., max_length=256, description="Tool name, file path, or n8n node ID")
    evidence: str = Field(..., max_length=4096, description="Concrete snippet or payload triggering the rule")
    remediation: str = Field(..., max_length=4096, description="Prescriptive remediation guidance")
    references: List[str] = Field(default_factory=list, description="Citations to OWASP, CVE, or security standards")
    false_positive_guidance: Optional[str] = Field(default=None, max_length=2048)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# 6. Risk Score Contract
class FactorBreakdown(BaseModel):
    impact: float = Field(..., ge=0.0, le=10.0, description="Damage severity if exploited")
    exploitability: float = Field(..., ge=0.0, le=10.0, description="Ease of triggering vulnerability")
    permission_scope: float = Field(..., ge=0.0, le=10.0, description="Breadth of tool capability")
    data_sensitivity: float = Field(..., ge=0.0, le=10.0, description="Classification level of involved data")
    destructive_capability: float = Field(..., ge=0.0, le=10.0, description="State destruction potential")
    exposure: float = Field(..., ge=0.0, le=10.0, description="Network / external accessibility")
    confidence_multiplier: float = Field(default=1.0, ge=0.5, le=1.0)


class RiskScore(BaseModel):
    numeric_score: float = Field(..., ge=0.0, le=100.0, description="Calculated 0-100 risk score")
    severity_band: Severity
    factor_breakdown: FactorBreakdown
    residual_risk: float = Field(..., ge=0.0, le=100.0, description="Estimated risk after proposed mitigations")
    recommended_action: str = Field(..., description="Actionable gate: ALLOW, REQUIRE_APPROVAL, or BLOCK")


# 7. Policy Rule Contract
class PolicyRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: f"POL-{uuid.uuid4().hex[:6].upper()}")
    name: str = Field(..., max_length=128)
    effect: PolicyEffect = Field(default=PolicyEffect.DENY)
    priority: int = Field(default=100, ge=1, le=1000, description="Evaluation order (lower = higher priority)")
    match_principals: List[str] = Field(default_factory=lambda: ["*"], description="Agent or user glob patterns")
    match_tools: List[str] = Field(default_factory=lambda: ["*"], description="Tool name glob patterns")
    match_conditions: Dict[str, Any] = Field(default_factory=dict, description="Argument criteria or regex filters")
    max_rate_per_minute: Optional[int] = Field(default=60, ge=1, le=10000)
    requires_approval_if_destructive: bool = Field(default=True)
    description: str = Field(default="", max_length=1024)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# 8. Approval Request Contract
class ApprovalRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: f"APPR-{uuid.uuid4().hex[:8].upper()}")
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    caller_agent_id: str
    risk_score: float
    reason: str
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    reviewer_id: Optional[str] = None
    reviewer_comments: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    decided_at: Optional[datetime] = None
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcfromtimestamp(datetime.utcnow().timestamp() + 3600)
    )


# 9. Audit Event Contract (Cryptographically chained)
class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:12]}")
    sequence_index: int = Field(..., ge=0)
    previous_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash of previous audit event")
    current_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash of this event record")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., max_length=64, description="e.g. TOOL_CALL, SCAN_COMPLETED, POLICY_BLOCKED")
    principal: str = Field(..., max_length=128)
    action: str = Field(..., max_length=128)
    decision: str = Field(..., max_length=32)
    payload_digest: str = Field(..., description="Digest or scrubbed summary of parameters")
    latency_ms: float = 0.0


# 10. n8n Workflow Finding Contract
class N8NWorkflowFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"N8N-{uuid.uuid4().hex[:8].upper()}")
    node_id: str = Field(..., max_length=128)
    node_name: str = Field(..., max_length=256)
    node_type: str = Field(..., max_length=256)
    rule_id: str = Field(..., max_length=64)
    severity: Severity
    issue_category: str = Field(..., max_length=128)
    evidence: str = Field(..., max_length=2048)
    fix_recommendation: str = Field(..., max_length=2048)


# 11. Scan Report Contract
class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: f"SCAN-{uuid.uuid4().hex[:10].upper()}")
    target_name: str = Field(..., max_length=256)
    target_type: str = Field(..., max_length=64, description="MCP_MANIFEST | MCP_SERVER | N8N_WORKFLOW")
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0
    tools_analyzed: int = 0
    nodes_analyzed: int = 0
    findings: List[SecurityFinding] = Field(default_factory=list)
    n8n_findings: List[N8NWorkflowFinding] = Field(default_factory=list)
    aggregate_risk: RiskScore
    summary_by_severity: Dict[str, int] = Field(default_factory=dict)
    compliance_checks_passed: int = 0
    compliance_checks_failed: int = 0
    sarif_output: Optional[Dict[str, Any]] = None
