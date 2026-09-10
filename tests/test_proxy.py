"""
Unit and Integration Tests for MCP Runtime Proxy & Security Engines
"""

import pytest
from backend.schemas.contracts import (
    ToolCall,
    ToolCallStatus,
    PolicyEffect,
    ToolDefinition,
    ToolPermission,
    PermissionScope,
    DataClassification,
)
from proxy.policy import PolicyEngine
from proxy.audit import AuditLedger
from proxy.redactor import OutputRedactor


@pytest.fixture
def policy_engine():
    engine = PolicyEngine()
    # Register test tools
    engine.register_tool(ToolDefinition(
        name="lookup_weather",
        description="Fetches weather.",
        parameters_schema={
            "type": "object",
            "properties": {
                "city": {"type": "string", "maxLength": 64, "pattern": "^[a-zA-Z\\s\\-]+$"}
            },
            "required": ["city"]
        },
        permissions=[ToolPermission(scope=PermissionScope.READ, data_classification=DataClassification.PUBLIC)]
    ))
    engine.register_tool(ToolDefinition(
        name="drop_database_table",
        description="Drops table.",
        parameters_schema={
            "type": "object",
            "properties": {
                "table_name": {"type": "string", "maxLength": 64},
                "confirm_purge": {"type": "boolean"}
            },
            "required": ["table_name", "confirm_purge"]
        },
        permissions=[ToolPermission(scope=PermissionScope.ADMIN, data_classification=DataClassification.RESTRICTED, is_destructive=True)]
    ))
    return engine


def test_deny_by_default_on_unregistered_tool(policy_engine):
    call = ToolCall(tool_name="unregistered_dangerous_tool", arguments={})
    decision, reason, app = policy_engine.evaluate_call(call)
    assert decision == PolicyEffect.DENY
    assert "not registered" in reason


def test_schema_length_violation(policy_engine):
    call = ToolCall(tool_name="lookup_weather", arguments={"city": "A" * 100})
    decision, reason, app = policy_engine.evaluate_call(call)
    assert decision == PolicyEffect.DENY
    assert "exceeds maximum length" in reason


def test_schema_pattern_violation(policy_engine):
    call = ToolCall(tool_name="lookup_weather", arguments={"city": "London; rm -rf /"})
    decision, reason, app = policy_engine.evaluate_call(call)
    assert decision == PolicyEffect.DENY
    assert "does not match required format pattern" in reason


def test_path_traversal_blocked(policy_engine):
    call = ToolCall(tool_name="lookup_weather", arguments={"city": "../../etc/shadow"})
    decision, reason, app = policy_engine.evaluate_call(call)
    assert decision == PolicyEffect.DENY
    assert "Path traversal" in reason or "pattern" in reason


def test_destructive_tool_requires_approval(policy_engine):
    call = ToolCall(
        call_id="call-del-1",
        tool_name="drop_database_table",
        arguments={"table_name": "temp_records", "confirm_purge": True}
    )
    decision, reason, app = policy_engine.evaluate_call(call)
    assert decision == PolicyEffect.REQUIRE_APPROVAL
    assert app is not None
    assert app.request_id in policy_engine.pending_approvals

    # Operator approves
    approved_app = policy_engine.approve_request(app.request_id, reviewer_id="admin", comment="OK")
    assert approved_app.status == "APPROVED"


def test_replay_detection(policy_engine):
    call = ToolCall(call_id="call-fixed-replay", tool_name="lookup_weather", arguments={"city": "Paris"})
    dec1, _, _ = policy_engine.evaluate_call(call)
    assert dec1 == PolicyEffect.ALLOW

    # Submitting identical call_id must be denied
    dec2, reas2, _ = policy_engine.evaluate_call(call)
    assert dec2 == PolicyEffect.DENY
    assert "Replay Attack" in reas2


def test_secret_redactor():
    secret_text = "Here is my key: sk-live-1234567890abcdef1234567890 and AWS AKIAIOSFODNN7EXAMPLE."
    cleaned, count = OutputRedactor.sanitize_text(secret_text)
    assert count >= 2
    assert "[REDACTED_API_KEY]" in cleaned
    assert "[REDACTED_AWS_KEY]" in cleaned
    assert "sk-live" not in cleaned
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned


def test_audit_ledger_cryptographic_integrity():
    ledger = AuditLedger()
    ev1 = ledger.record_event("CALL", "agent1", "tool1", "ALLOW", {"arg": 1}, 5.0)
    ev2 = ledger.record_event("CALL", "agent1", "tool2", "ALLOW", {"arg": 2}, 3.0)
    ev3 = ledger.record_event("CALL", "agent1", "tool3", "DENY", {"arg": 3}, 1.0)

    # Initial check must pass
    status = ledger.verify_integrity()
    assert status["is_valid"] is True
    assert status["events_verified"] == 3

    # Tampering: modify payload digest of event 1
    ledger.events[1].payload_digest = "corrupted_digest_data"
    tampered_status = ledger.verify_integrity()
    assert tampered_status["is_valid"] is False
    assert tampered_status["corrupted_at_index"] == 1
