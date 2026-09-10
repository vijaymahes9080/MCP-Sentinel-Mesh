"""
MCP Sentinel Mesh - OpenTelemetry Tracing & Prometheus Metrics Exporter
Standardized observability conforming to gen_ai.system and mcp.tool semantic conventions.
"""

import time
from typing import Dict, Any, Optional, List
from collections import defaultdict


class SentinelTelemetry:
    """
    In-memory OpenTelemetry trace emitter & Prometheus metrics accumulator.
    """

    def __init__(self):
        # Metrics storage
        self.tool_calls_total: Dict[str, int] = defaultdict(int)  # key: (tool, decision, principal)
        self.policy_blocks_total: Dict[str, int] = defaultdict(int)  # key: (tool, reason)
        self.call_latencies: Dict[str, List[float]] = defaultdict(list)  # tool -> [seconds]
        self.active_approvals_gauge: int = 0
        self.spans: List[Dict[str, Any]] = []

    def record_span(
        self,
        trace_id: str,
        span_id: str,
        tool_name: str,
        caller_agent_id: str,
        decision: str,
        latency_ms: float,
        attributes: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates an OpenTelemetry span conforming to gen_ai semantic conventions."""
        span = {
            "trace_id": trace_id,
            "span_id": span_id,
            "name": f"mcp.tool_call/{tool_name}",
            "kind": "SERVER",
            "start_time": time.time() - (latency_ms / 1000.0),
            "end_time": time.time(),
            "attributes": {
                "gen_ai.system": "mcp_sentinel_mesh",
                "mcp.tool.name": tool_name,
                "mcp.caller.agent_id": caller_agent_id,
                "mcp.policy.decision": decision,
                "mcp.execution.latency_ms": latency_ms,
                **(attributes or {})
            }
        }
        self.spans.append(span)

        # Update metrics
        key_call = f'tool="{tool_name}",decision="{decision}",principal="{caller_agent_id}"'
        self.tool_calls_total[key_call] += 1

        if decision == "DENY":
            key_block = f'tool="{tool_name}"'
            self.policy_blocks_total[key_block] += 1

        self.call_latencies[tool_name].append(latency_ms / 1000.0)
        return span

    def set_active_approvals(self, count: int):
        self.active_approvals_gauge = count

    def generate_prometheus_metrics(self) -> str:
        """Emits standard Prometheus text format exposition (v0.0.4)."""
        lines = []
        lines.append("# HELP mcp_sentinel_tool_calls_total Total tool calls mediated by Sentinel Mesh.")
        lines.append("# TYPE mcp_sentinel_tool_calls_total counter")
        for labels, count in self.tool_calls_total.items():
            lines.append(f"mcp_sentinel_tool_calls_total{{{labels}}} {count}")

        lines.append("# HELP mcp_sentinel_policy_blocks_total Total calls blocked by policy engine.")
        lines.append("# TYPE mcp_sentinel_policy_blocks_total counter")
        for labels, count in self.policy_blocks_total.items():
            lines.append(f"mcp_sentinel_policy_blocks_total{{{labels}}} {count}")

        lines.append("# HELP mcp_sentinel_active_approvals Current pending human approval requests.")
        lines.append("# TYPE mcp_sentinel_active_approvals gauge")
        lines.append(f"mcp_sentinel_active_approvals {self.active_approvals_gauge}")

        return "\n".join(lines) + "\n"
