"""
Unit Tests for OpenTelemetry Tracing and Prometheus Metrics Exporter
"""

import pytest
from proxy.telemetry import SentinelTelemetry


def test_record_span_and_prometheus_export():
    telem = SentinelTelemetry()

    # Record 2 allowed spans and 1 blocked span
    telem.record_span("trace-1", "span-1", "lookup_weather", "agent-a", "ALLOW", 12.5)
    telem.record_span("trace-2", "span-2", "lookup_weather", "agent-a", "ALLOW", 14.1)
    telem.record_span("trace-3", "span-3", "read_file_safe", "agent-b", "DENY", 2.3)
    telem.set_active_approvals(3)

    assert len(telem.spans) == 3
    assert telem.spans[0]["attributes"]["gen_ai.system"] == "mcp_sentinel_mesh"
    assert telem.spans[0]["attributes"]["mcp.tool.name"] == "lookup_weather"

    prom = telem.generate_prometheus_metrics()
    assert "mcp_sentinel_tool_calls_total" in prom
    assert 'tool="lookup_weather",decision="ALLOW",principal="agent-a"} 2' in prom
    assert 'tool="read_file_safe",decision="DENY",principal="agent-b"} 1' in prom
    assert "mcp_sentinel_policy_blocks_total" in prom
    assert "mcp_sentinel_active_approvals 3" in prom
