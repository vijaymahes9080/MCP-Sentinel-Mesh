"""
Unit Tests for Multi-Agent Swarm Simulator
"""

import pytest
from scanner.bot_simulator import SwarmSimulator, AgentPersona


def test_swarm_simulator_persona_isolation():
    sim = SwarmSimulator()
    metrics = sim.run_simulation()

    assert metrics["total_calls"] == 8
    # Research bot safe calls should pass
    assert metrics["by_persona"][AgentPersona.RESEARCH_BOT]["allowed"] == 3
    assert metrics["by_persona"][AgentPersona.RESEARCH_BOT]["blocked"] == 0

    # Malicious insider attacks should be completely neutralized
    assert metrics["by_persona"][AgentPersona.MALICIOUS_INSIDER]["blocked"] == 3
    assert metrics["by_persona"][AgentPersona.MALICIOUS_INSIDER]["allowed"] == 0

    # DevOps bot triggers human approval requirements
    assert metrics["by_persona"][AgentPersona.DEVOPS_BOT]["approvals"] >= 1
