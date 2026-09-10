"""
Mock High-Risk MCP Server
Simulates dangerous administrative tools (shell execution, database table drop) under strict safety boundaries.
"""

import sys
import os
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
adapter_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters")
sys.path.insert(0, adapter_dir)

from backend.schemas.contracts import ToolDefinition, ToolPermission, PermissionScope, DataClassification
from adapter import MCPProtocolAdapter


def execute_shell_command_handler(args: Dict[str, Any]) -> Dict[str, Any]:
    cmd = args.get("command", "echo test")
    # Synthetic safe mock: Do NOT execute real arbitrary shell commands
    return {
        "executed_command": cmd,
        "stdout": f"[MOCK-DRY-RUN] Simulated execution of: {cmd}",
        "exit_code": 0,
        "note": "Executed under safe synthetic test sandbox."
    }


def drop_database_table_handler(args: Dict[str, Any]) -> Dict[str, Any]:
    table = args.get("table_name", "temp_table")
    confirm = args.get("confirm_purge", False)
    if not confirm:
        raise ValueError("Confirmation flag 'confirm_purge' must be explicitly set to True.")
    return {
        "status": "dropped",
        "table": table,
        "records_affected": 4200,
        "note": "Simulated drop operation executed."
    }


def create_high_risk_adapter() -> MCPProtocolAdapter:
    adapter = MCPProtocolAdapter(server_id="mock-high-risk-server")

    tool1 = ToolDefinition(
        name="execute_shell_command",
        description="Executes raw shell script on underlying container host.",
        parameters_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "maxLength": 1024},
                "working_dir": {"type": "string", "maxLength": 256}
            },
            "required": ["command"]
        },
        permissions=[
            ToolPermission(scope=PermissionScope.EXECUTE, resource_patterns=["*"], data_classification=DataClassification.RESTRICTED, is_destructive=True)
        ]
    )

    tool2 = ToolDefinition(
        name="drop_database_table",
        description="Drops an entire database table or schema and purges all associated audit tables.",
        parameters_schema={
            "type": "object",
            "properties": {
                "table_name": {"type": "string", "maxLength": 64},
                "confirm_purge": {"type": "boolean"}
            },
            "required": ["table_name", "confirm_purge"]
        },
        permissions=[
            ToolPermission(scope=PermissionScope.ADMIN, resource_patterns=["database/tables/*"], data_classification=DataClassification.RESTRICTED, is_destructive=True)
        ]
    )

    adapter.register_tool(tool1, execute_shell_command_handler)
    adapter.register_tool(tool2, drop_database_table_handler)
    return adapter


if __name__ == "__main__":
    adapter = create_high_risk_adapter()
    print(f"High-Risk MCP Adapter initialized with tools: {list(adapter.tools_registry.keys())}")
