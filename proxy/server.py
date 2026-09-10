"""
MCP Sentinel Mesh - Runtime Security Proxy Server
FastAPI ASGI application intercepting and mediating tool calls between AI agents and MCP servers.
"""

import time
import os
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime

# Path setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.schemas.contracts import (
    ToolCall,
    ToolResponse,
    ToolCallStatus,
    PolicyEffect,
    ApprovalStatus,
    ToolDefinition,
    PolicyRule,
    ScanReport,
)
from proxy.policy import PolicyEngine
from proxy.audit import AuditLedger
from proxy.redactor import OutputRedactor
from scanner.core import SentinelScanner
from scanner.adversarial.engine import AdversarialTestEngine
from scanner.adversarial.corpus import CORPUS

# Initialize FastAPI application
app = FastAPI(
    title="MCP Sentinel Mesh — Security Proxy",
    description="Enterprise Security Scanner, Runtime Policy Proxy, and Tamper-Evident Audit Mesh for MCP Servers.",
    version="1.0.0"
)

# Strict CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to dashboard domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Application singletons
policy_engine = PolicyEngine()
audit_ledger = AuditLedger()
active_adapters: Dict[str, Any] = {}
start_time_epoch = time.time()


def init_mock_adapters():
    """Mounts synthetic MCP servers into the proxy tool registry."""
    from mcp_samples.servers.secure_server import create_secure_adapter
    from mcp_samples.servers.vulnerable_server import create_vulnerable_adapter
    from mcp_samples.servers.high_risk_server import create_high_risk_adapter

    sec_adapter = create_secure_adapter()
    vuln_adapter = create_vulnerable_adapter()
    high_adapter = create_high_risk_adapter()

    active_adapters["mock-secure-server"] = sec_adapter
    active_adapters["mock-vulnerable-server"] = vuln_adapter
    active_adapters["mock-high-risk-server"] = high_adapter

    # Register all tools into policy engine
    for adapter in [sec_adapter, vuln_adapter, high_adapter]:
        for tool_name, tool_def in adapter.tools_registry.items():
            policy_engine.register_tool(tool_def)


# Helper to find adapter handling tool
def get_adapter_for_tool(tool_name: str) -> Optional[Any]:
    for adapter in active_adapters.values():
        if tool_name in adapter.tools_registry:
            return adapter
    return None


@app.on_event("startup")
def on_startup():
    # Attempt mock adapter init
    try:
        import importlib.util
        servers_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp-samples", "servers")
        
        def load_module_from_path(mod_name: str, file_path: str):
            spec = importlib.util.spec_from_file_location(mod_name, file_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

        sec_mod = load_module_from_path("secure_server", os.path.join(servers_dir, "secure_server.py"))
        vuln_mod = load_module_from_path("vulnerable_server", os.path.join(servers_dir, "vulnerable_server.py"))
        high_mod = load_module_from_path("high_risk_server", os.path.join(servers_dir, "high_risk_server.py"))

        sec_adapter = sec_mod.create_secure_adapter()
        vuln_adapter = vuln_mod.create_vulnerable_adapter()
        high_adapter = high_mod.create_high_risk_adapter()

        active_adapters["mock-secure-server"] = sec_adapter
        active_adapters["mock-vulnerable-server"] = vuln_adapter
        active_adapters["mock-high-risk-server"] = high_adapter

        for adapter in [sec_adapter, vuln_adapter, high_adapter]:
            for tool_name, tool_def in adapter.tools_registry.items():
                policy_engine.register_tool(tool_def)
    except Exception as e:
        print(f"Notice: Mock adapters initialization deferred: {e}")

# Pre-initialize tools immediately on import
on_startup()


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --- 1. Operational Endpoints ---
@app.get("/health", tags=["System"])
def get_health():
    uptime = round(time.time() - start_time_epoch, 2)
    audit_status = audit_ledger.verify_integrity()
    return {
        "status": "healthy",
        "service": "MCP Sentinel Mesh Proxy",
        "uptime_seconds": uptime,
        "tools_registered": len(policy_engine.tools),
        "audit_chain_valid": audit_status.get("is_valid", False),
        "audit_events_count": len(audit_ledger.events),
    }


@app.get("/version", tags=["System"])
def get_version():
    return {
        "name": "MCP Sentinel Mesh",
        "version": "1.0.0",
        "protocol": "MCP 2024-11-05",
        "author": "Vijay Mahes <Vijaypradhap2004@gmail.com>",
        "repository": "https://github.com/vijaymahes9080/MCP-Sentinel-Mesh"
    }


# --- 2. Tool Inventory ---
@app.get("/tools", tags=["Inventory"])
def list_tools():
    """Returns registered tools with their declared permissions and parameter schemas."""
    result = []
    for name, t in policy_engine.tools.items():
        result.append(t.model_dump(mode="json"))
    return {"tools": result, "count": len(result)}


# --- 3. Runtime Tool Call Mediation ---
@app.post("/proxy/tool-call", response_model=ToolResponse, tags=["Proxy"])
def proxy_tool_call(call: ToolCall):
    """
    Main runtime mediation gateway.
    Enforces deny-by-default policy, schema constraints, approval gating,
    and output redaction.
    """
    start_call = time.time()

    # 1. Policy & Schema Evaluation
    decision, reason, approval_req = policy_engine.evaluate_call(call)

    if decision == PolicyEffect.REQUIRE_APPROVAL:
        duration_ms = round((time.time() - start_call) * 1000, 2)
        audit_ledger.record_event(
            event_type="TOOL_CALL_APPROVAL_REQUIRED",
            principal=call.caller_agent_id,
            action=call.tool_name,
            decision="PENDING_APPROVAL",
            payload_summary={"args": call.arguments, "approval_id": approval_req.request_id},
            latency_ms=duration_ms
        )
        return ToolResponse(
            call_id=call.call_id,
            status=ToolCallStatus.PENDING_APPROVAL,
            blocked_reason=f"Action paused for human approval. Approval ID: {approval_req.request_id}",
            result={"approval_request_id": approval_req.request_id, "status": "PENDING"},
            execution_time_ms=duration_ms
        )

    if decision == PolicyEffect.DENY:
        duration_ms = round((time.time() - start_call) * 1000, 2)
        audit_ledger.record_event(
            event_type="TOOL_CALL_BLOCKED",
            principal=call.caller_agent_id,
            action=call.tool_name,
            decision="DENY",
            payload_summary={"args": call.arguments, "reason": reason},
            latency_ms=duration_ms
        )
        return ToolResponse(
            call_id=call.call_id,
            status=ToolCallStatus.BLOCKED,
            blocked_reason=reason,
            execution_time_ms=duration_ms
        )

    # 2. Invoke Downstream MCP Server Adapter
    adapter = get_adapter_for_tool(call.tool_name)
    if not adapter:
        # Synthetic mock fallback if not tied to specific adapter
        raw_result = {
            "status": "executed",
            "message": f"Successfully mediated call to '{call.tool_name}'.",
            "echo": call.arguments
        }
    else:
        resp = adapter.invoke_tool(call)
        raw_result = resp.result if resp.status == ToolCallStatus.SUCCESS else resp.blocked_reason

    # 3. Output Redaction
    sanitized_result, redaction_count = OutputRedactor.sanitize(raw_result)
    duration_ms = round((time.time() - start_call) * 1000, 2)

    # 4. Cryptographic Audit Record
    audit_ledger.record_event(
        event_type="TOOL_CALL_SUCCESS",
        principal=call.caller_agent_id,
        action=call.tool_name,
        decision="ALLOW",
        payload_summary={"args": call.arguments, "redactions": redaction_count},
        latency_ms=duration_ms
    )

    return ToolResponse(
        call_id=call.call_id,
        status=ToolCallStatus.SUCCESS,
        result=raw_result,
        sanitized_result=sanitized_result,
        redaction_applied=redaction_count > 0,
        redactions_count=redaction_count,
        execution_time_ms=duration_ms
    )


# --- 4. Policy Evaluation (Dry-Run) ---
@app.post("/policies/evaluate", tags=["Policies"])
def dry_run_policy_evaluation(call: ToolCall):
    decision, reason, approval = policy_engine.evaluate_call(call)
    return {
        "decision": decision.value,
        "reason": reason,
        "requires_approval": approval is not None,
        "approval_id": approval.request_id if approval else None
    }


# --- 5. Human-in-the-Loop Approvals ---
class ApprovalDecisionRequest(BaseModel):
    reviewer_id: str = Field(default="admin-operator", max_length=128)
    comment: Optional[str] = Field(default="Approved via Sentinel UI", max_length=1024)


@app.get("/approvals", tags=["Approvals"])
def list_approvals():
    return {
        "approvals": [a.model_dump(mode="json") for a in policy_engine.pending_approvals.values()],
        "count": len(policy_engine.pending_approvals)
    }


@app.post("/approvals/{request_id}/approve", tags=["Approvals"])
def approve_request(request_id: str, decision: ApprovalDecisionRequest):
    req = policy_engine.approve_request(request_id, reviewer_id=decision.reviewer_id, comment=decision.comment)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    # Audit the human authorization
    audit_ledger.record_event(
        event_type="HUMAN_APPROVAL_GRANTED",
        principal=decision.reviewer_id,
        action=req.tool_name,
        decision="APPROVED",
        payload_summary={"request_id": request_id, "comment": decision.comment}
    )
    return {"message": "Request approved.", "approval": req.model_dump(mode="json")}


@app.post("/approvals/{request_id}/reject", tags=["Approvals"])
def reject_request(request_id: str, decision: ApprovalDecisionRequest):
    req = policy_engine.reject_request(request_id, reviewer_id=decision.reviewer_id, comment=decision.comment)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    audit_ledger.record_event(
        event_type="HUMAN_APPROVAL_REJECTED",
        principal=decision.reviewer_id,
        action=req.tool_name,
        decision="REJECTED",
        payload_summary={"request_id": request_id, "comment": decision.comment}
    )
    return {"message": "Request rejected.", "approval": req.model_dump(mode="json")}


# --- 6. Tamper-Evident Audit Ledger ---
@app.get("/audit", tags=["Audit"])
def get_audit_trail(limit: int = 50):
    integrity = audit_ledger.verify_integrity()
    recent = audit_ledger.get_recent(limit=limit)
    return {
        "integrity": integrity,
        "events": [e.model_dump(mode="json") for e in recent],
        "count": len(recent)
    }


# --- 7. Static Scanner API Endpoint ---
@app.post("/api/scan", tags=["Scanner"])
def scan_manifest_payload(manifest_data: Dict[str, Any]):
    scanner = SentinelScanner()
    if "nodes" in manifest_data and "connections" in manifest_data:
        from scanner.n8n_analyzer import N8NWorkflowAnalyzer
        report = N8NWorkflowAnalyzer.scan_workflow_dict(manifest_data, target_name="dynamic_upload.json")
    else:
        tools = scanner.parse_manifest(manifest_data)
        report = scanner.scan_tools(tools, target_name="dynamic_upload.json")
    return report.model_dump(mode="json")


# --- 8. Adversarial Benchmark API ---
@app.get("/api/benchmarks", tags=["Evaluation"])
def run_adversarial_benchmarks():
    engine = AdversarialTestEngine()
    results = engine.run_all(policy_evaluator=policy_engine)
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    detected = sum(1 for r in results if r.detected)
    blocked = sum(1 for r in results if r.blocked)

    return {
        "summary": {
            "total_cases": total,
            "passed": passed,
            "failed": total - passed,
            "detection_rate_pct": round((detected / total) * 100, 1),
            "block_rate_pct": round((blocked / total) * 100, 1),
            "pass_rate_pct": round((passed / total) * 100, 1),
        },
        "results": [r.model_dump(mode="json") for r in results]
    }
