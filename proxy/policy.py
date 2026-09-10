"""
MCP Sentinel Mesh - Runtime Policy Enforcement Engine
Evaluates tool calls against deny-by-default policies, rate limits, schema validation, and approval workflows.
"""

import time
import re
import fnmatch
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

from backend.schemas.contracts import (
    ToolCall,
    ToolDefinition,
    PolicyRule,
    PolicyEffect,
    ApprovalRequest,
    ApprovalStatus,
    PermissionScope,
    DataClassification,
)


class PolicyEngine:
    """
    Stateful runtime policy engine enforcing:
    - Deny-by-default
    - Schema parameter constraints
    - Sliding window rate limiting
    - Replay protection
    - Human approval gating
    """

    def __init__(self):
        self.rules: List[PolicyRule] = []
        self.tools: Dict[str, ToolDefinition] = {}
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.seen_nonces: Dict[str, float] = {}  # Nonce/call_id -> timestamp
        self.call_rate_history: Dict[str, List[float]] = defaultdict(list)  # Principal -> timestamps

        # Bootstrap default baseline policy rules
        self._init_default_rules()

    def _init_default_rules(self):
        """Initializes secure default policy set."""
        # Rule 1: Require approval for destructive administrative actions
        self.rules.append(PolicyRule(
            rule_id="POL-DEFAULT-001",
            name="Require Approval for Destructive or Admin Tools",
            effect=PolicyEffect.REQUIRE_APPROVAL,
            priority=10,
            match_principals=["*"],
            match_tools=["execute_shell_command", "drop_database_table", "*_delete*", "*_purge*", "*_drop*"],
            requires_approval_if_destructive=True,
            description="Blocks direct execution of destructive operations without human approval."
        ))

        # Rule 2: Deny any internal loopback or cloud metadata network egress
        self.rules.append(PolicyRule(
            rule_id="POL-DEFAULT-002",
            name="Block Internal and Cloud Metadata SSRF Egress",
            effect=PolicyEffect.DENY,
            priority=20,
            match_principals=["*"],
            match_tools=["*"],
            match_conditions={"forbidden_ip_patterns": [r"169\.254\.169\.254", r"127\.0\.0\.1", r"localhost", r"10\.\d+\.\d+\.\d+"]},
            description="Denies egress calls targeting cloud instance metadata or loopback."
        ))

        # Rule 3: Allow standard read-only telemetry and weather lookups with rate limits
        self.rules.append(PolicyRule(
            rule_id="POL-DEFAULT-003",
            name="Allow Safe Read-Only Utilities",
            effect=PolicyEffect.ALLOW,
            priority=100,
            match_principals=["*"],
            match_tools=["get_system_health", "lookup_weather"],
            max_rate_per_minute=120,
            description="Permits read-only queries subject to rate limiting."
        ))

    def register_tool(self, tool: ToolDefinition):
        self.tools[tool.name] = tool

    def check_replay_and_nonce(self, call: ToolCall) -> Tuple[bool, Optional[str]]:
        """Replay detection: checks if call_id or nonce has been seen recently."""
        now = time.time()
        # Clean up entries older than 300 seconds
        stale_keys = [k for k, t in self.seen_nonces.items() if now - t > 300]
        for k in stale_keys:
            del self.seen_nonces[k]

        nonce_key = f"{call.tenant_id}:{call.call_id}"
        if nonce_key in self.seen_nonces:
            return False, f"Duplicate tool call detected (Replay Attack): {call.call_id} was already executed."

        custom_nonce = call.arguments.get("nonce")
        if custom_nonce:
            custom_key = f"{call.tenant_id}:{custom_nonce}"
            if custom_key in self.seen_nonces:
                return False, f"Duplicate nonce token detected: '{custom_nonce}' has already been processed."
            self.seen_nonces[custom_key] = now

        self.seen_nonces[nonce_key] = now
        return True, None

    def check_rate_limits(self, principal: str, limit_per_min: int = 60) -> Tuple[bool, Optional[str]]:
        """Sliding-window rate limiter."""
        now = time.time()
        window_start = now - 60.0
        # Filter timestamps within window
        calls = [t for t in self.call_rate_history[principal] if t > window_start]
        if len(calls) >= limit_per_min:
            return False, f"Rate limit exceeded: Principal '{principal}' has made {len(calls)} calls in the past 60s (Limit: {limit_per_min}/min)."

        calls.append(now)
        self.call_rate_history[principal] = calls
        return True, None

    def validate_arguments_against_schema(self, tool: ToolDefinition, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Strict JSONSchema parameter checks."""
        schema = tool.parameters_schema
        props = schema.get("properties", {})
        required = schema.get("required", [])

        # Check required fields
        for req in required:
            if req not in args:
                return False, f"Missing required parameter '{req}' for tool '{tool.name}'."

        # Check types, lengths, and patterns
        for param_name, val in args.items():
            param_spec = props.get(param_name)
            if not param_spec:
                # Disallow unknown arguments if properties are defined
                if props:
                    return False, f"Unknown parameter '{param_name}' not defined in tool schema."
                continue

            expected_type = param_spec.get("type")
            if expected_type == "string":
                if not isinstance(val, str):
                    return False, f"Type mismatch for parameter '{param_name}': expected string, got {type(val).__name__}."
                max_len = param_spec.get("maxLength")
                if max_len and len(val) > max_len:
                    return False, f"Parameter '{param_name}' exceeds maximum length of {max_len} (received {len(val)} chars)."
                pattern = param_spec.get("pattern")
                if pattern and not re.match(pattern, val):
                    return False, f"Parameter '{param_name}' does not match required format pattern '{pattern}'."
                enum_vals = param_spec.get("enum")
                if enum_vals and val not in enum_vals:
                    return False, f"Parameter '{param_name}' value '{val}' not in permitted enum: {enum_vals}."

            elif expected_type in ["integer", "number"]:
                if not isinstance(val, (int, float)) or isinstance(val, bool):
                    return False, f"Type mismatch for parameter '{param_name}': expected number, got {type(val).__name__}."

            elif expected_type == "boolean":
                if not isinstance(val, bool):
                    return False, f"Type mismatch for parameter '{param_name}': expected boolean, got {type(val).__name__}."

        return True, None

    def evaluate_call(self, call: ToolCall) -> Tuple[PolicyEffect, str, Optional[ApprovalRequest]]:
        """
        Main decision gate:
        1. Check replay / nonce
        2. Check tool exists
        3. Validate schema & bounds
        4. Check rate limit
        5. Evaluate policy rules in priority order
        """
        # 1. Replay & Nonce Check
        nonce_ok, nonce_err = self.check_replay_and_nonce(call)
        if not nonce_ok:
            return PolicyEffect.DENY, nonce_err, None

        # 2. Unknown Tool Check (Deny by Default)
        if call.tool_name not in self.tools:
            return PolicyEffect.DENY, f"Tool '{call.tool_name}' is not registered in the Sentinel tool catalog. Deny by default.", None

        tool = self.tools[call.tool_name]

        # 3. Schema & Bounds Check
        schema_ok, schema_err = self.validate_arguments_against_schema(tool, call.arguments)
        if not schema_ok:
            return PolicyEffect.DENY, f"Schema validation failed: {schema_err}", None

        # 4. Global Injection & Path Traversal Heuristic Filter on Arguments
        args_str = str(call.arguments)
        if re.search(r"\.\./", args_str) or "/etc/" in args_str or "~/.ssh" in args_str:
            return PolicyEffect.DENY, "Path traversal pattern detected in tool arguments.", None

        if re.search(r"(?i)ignore\s+(all\s+)?previous\s+instructions", args_str):
            return PolicyEffect.DENY, "Prompt injection attempt detected in tool arguments.", None

        # Check internal IP SSRF
        for pattern in [r"169\.254\.169\.254", r"127\.0\.0\.1", r"localhost", r"10\.\d+\.\d+\.\d+"]:
            if re.search(pattern, args_str):
                return PolicyEffect.DENY, f"Egress to internal address ({pattern}) blocked by Sentinel policy.", None

        # 5. Rate Limit Check
        rl_ok, rl_err = self.check_rate_limits(call.caller_agent_id)
        if not rl_ok:
            return PolicyEffect.DENY, rl_err, None

        # 6. Evaluate Loaded Rules in Priority Order (lower number = higher priority)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority)
        for rule in sorted_rules:
            # Check principal match
            principal_match = any(fnmatch.fnmatch(call.caller_agent_id, p) for p in rule.match_principals)
            if not principal_match:
                continue

            # Check tool match
            tool_match = any(fnmatch.fnmatch(call.tool_name, t) for t in rule.match_tools)
            if not tool_match:
                continue

            # Check match_conditions if specified
            if rule.match_conditions:
                forbidden_ips = rule.match_conditions.get("forbidden_ip_patterns", [])
                if forbidden_ips:
                    has_ip_match = any(re.search(pat, args_str) for pat in forbidden_ips)
                    if not has_ip_match:
                        # Conditions did not match, skip this rule
                        continue

            # Check destructive condition
            is_tool_destructive = any(p.is_destructive for p in tool.permissions)
            if rule.requires_approval_if_destructive and is_tool_destructive:
                # Create Approval Request
                approval = ApprovalRequest(
                    call_id=call.call_id,
                    tool_name=call.tool_name,
                    arguments=call.arguments,
                    caller_agent_id=call.caller_agent_id,
                    risk_score=85.0,
                    reason=f"Tool '{call.tool_name}' performs destructive state mutations. Operator authorization required."
                )
                self.pending_approvals[approval.request_id] = approval
                return PolicyEffect.REQUIRE_APPROVAL, f"Tool '{call.tool_name}' requires human approval. Approval request ID: {approval.request_id}", approval

            if rule.effect == PolicyEffect.REQUIRE_APPROVAL:
                approval = ApprovalRequest(
                    call_id=call.call_id,
                    tool_name=call.tool_name,
                    arguments=call.arguments,
                    caller_agent_id=call.caller_agent_id,
                    risk_score=75.0,
                    reason=f"Triggered policy rule '{rule.name}'"
                )
                self.pending_approvals[approval.request_id] = approval
                return PolicyEffect.REQUIRE_APPROVAL, f"Tool '{call.tool_name}' requires human approval by policy rule '{rule.name}'. Request ID: {approval.request_id}", approval

            if rule.effect == PolicyEffect.DENY:
                return PolicyEffect.DENY, f"Call blocked by policy rule '{rule.name}'.", None

            if rule.effect == PolicyEffect.ALLOW:
                return PolicyEffect.ALLOW, f"Call permitted under policy rule '{rule.name}'.", None

        # Default fallback
        return PolicyEffect.DENY, "No matching policy rule found. Deny by default.", None

    def approve_request(self, request_id: str, reviewer_id: str, comment: Optional[str] = None) -> Optional[ApprovalRequest]:
        req = self.pending_approvals.get(request_id)
        if not req:
            return None
        req.status = ApprovalStatus.APPROVED
        req.reviewer_id = reviewer_id
        req.reviewer_comments = comment or "Approved by operator."
        return req

    def reject_request(self, request_id: str, reviewer_id: str, comment: Optional[str] = None) -> Optional[ApprovalRequest]:
        req = self.pending_approvals.get(request_id)
        if not req:
            return None
        req.status = ApprovalStatus.REJECTED
        req.reviewer_id = reviewer_id
        req.reviewer_comments = comment or "Rejected by operator."
        return req
