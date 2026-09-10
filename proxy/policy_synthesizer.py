"""
MCP Sentinel Mesh - Autonomous Policy Synthesizer
Synthesizes zero-trust, least-privilege YAML/JSON access policies from observed agent runtime execution traces.
"""

from typing import List, Dict, Any
from collections import defaultdict
import json


class PolicySynthesizer:
    """
    Analyzes historical audit logs and tool calls to automatically generate
    minimal least-privilege security policies.
    """

    DANGEROUS_ACTIONS = ["delete", "drop", "destroy", "execute", "shell", "chmod", "kill", "wipe"]

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []

    def record_call(self, agent_id: str, server_name: str, tool_name: str, arguments: Dict[str, Any], allowed: bool = True):
        """Records an observed tool invocation in the synthesis trace."""
        self.invocations.append({
            "agent_id": agent_id,
            "server_name": server_name,
            "tool_name": tool_name,
            "arguments": arguments,
            "allowed": allowed
        })

    def synthesize_rules(self) -> Dict[str, Any]:
        """
        Synthesizes a declarative policy specification restricting agents to strictly observed behaviors.
        """
        agent_tools = defaultdict(lambda: defaultdict(lambda: {"call_count": 0, "param_keys": set()}))

        for inv in self.invocations:
            if not inv.get("allowed", True):
                continue
            agent = inv.get("agent_id", "default_agent")
            server = inv.get("server_name", "default_server")
            tool = inv.get("tool_name", "unknown")
            args = inv.get("arguments", {})

            entry = agent_tools[agent][tool]
            entry["call_count"] += 1
            entry["server"] = server
            if isinstance(args, dict):
                for k in args.keys():
                    entry["param_keys"].add(k)

        policies = []
        for agent, tools in agent_tools.items():
            rules = []
            for tool, data in tools.items():
                is_dangerous = any(d in tool.lower() for d in self.DANGEROUS_ACTIONS)
                rule = {
                    "tool": tool,
                    "server": data.get("server", "*"),
                    "action": "allow",
                    "require_approval": is_dangerous,
                    "allowed_parameters": sorted(list(data["param_keys"])),
                    "observed_invocations": data["call_count"]
                }
                rules.append(rule)

            policies.append({
                "agent_id": agent,
                "default_action": "deny",  # Strict Zero-Trust Default
                "rules": rules
            })

        return {
            "version": "sentinel.mesh/v1alpha1",
            "metadata": {
                "generated_by": "SentinelMesh-Autonomous-PolicySynthesizer",
                "total_traces_analyzed": len(self.invocations)
            },
            "policies": policies
        }

    def export_json(self, indent: int = 2) -> str:
        """Exports the synthesized policy as formatted JSON."""
        return json.dumps(self.synthesize_rules(), indent=indent)
