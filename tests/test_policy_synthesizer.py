"""
Unit Tests for Autonomous Policy Synthesizer
"""

import pytest
import json
from proxy.policy_synthesizer import PolicySynthesizer


def test_policy_synthesizer_generates_zero_trust_rules():
    synthesizer = PolicySynthesizer()

    # Feed traces for research bot
    synthesizer.record_call(
        agent_id="research_bot",
        server_name="docs_server",
        tool_name="search_docs",
        arguments={"query": "oauth2", "limit": 10},
        allowed=True
    )
    synthesizer.record_call(
        agent_id="research_bot",
        server_name="docs_server",
        tool_name="read_page",
        arguments={"page_id": "p-123"},
        allowed=True
    )

    # Feed trace for admin bot with dangerous tool
    synthesizer.record_call(
        agent_id="admin_bot",
        server_name="db_server",
        tool_name="drop_table",
        arguments={"table": "users_temp"},
        allowed=True
    )

    policy_spec = synthesizer.synthesize_rules()

    assert policy_spec["version"] == "sentinel.mesh/v1alpha1"
    assert policy_spec["metadata"]["total_traces_analyzed"] == 3

    policies = {p["agent_id"]: p for p in policy_spec["policies"]}
    assert "research_bot" in policies
    assert "admin_bot" in policies

    # Research bot policy check
    r_rules = {r["tool"]: r for r in policies["research_bot"]["rules"]}
    assert "search_docs" in r_rules
    assert r_rules["search_docs"]["require_approval"] is False
    assert set(r_rules["search_docs"]["allowed_parameters"]) == {"query", "limit"}

    # Admin bot policy check
    a_rules = {r["tool"]: r for r in policies["admin_bot"]["rules"]}
    assert "drop_table" in a_rules
    assert a_rules["drop_table"]["require_approval"] is True  # Flags destructive action

    # JSON export
    json_out = synthesizer.export_json()
    assert "sentinel.mesh/v1alpha1" in json_out
