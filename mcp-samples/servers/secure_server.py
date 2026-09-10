"""
Mock Secure MCP Server
Provides safe, read-only telemetry and weather lookups.
"""

from typing import Dict, Any
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.schemas.contracts import ToolDefinition, ToolPermission, PermissionScope, DataClassification

# Import adapter directly from file path or relative
adapter_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters")
sys.path.insert(0, adapter_dir)
from adapter import MCPProtocolAdapter


def get_system_health_handler(args: Dict[str, Any]) -> Dict[str, Any]:
    metric = args.get("metric_type", "all")
    return {
        "status": "healthy",
        "cpu_percent": 12.4,
        "memory_used_mb": 512,
        "uptime_seconds": 86400,
        "requested_metric": metric
    }


def lookup_weather_handler(args: Dict[str, Any]) -> Dict[str, Any]:
    city = args.get("city", "Chennai")
    return {
        "city": city,
        "temperature_c": 29.5,
        "condition": "Partly Cloudy",
        "humidity_percent": 68
    }


def create_secure_adapter() -> MCPProtocolAdapter:
    adapter = MCPProtocolAdapter(server_id="mock-secure-server")

    tool1 = ToolDefinition(
        name="get_system_health",
        description="Retrieves current CPU, memory, and uptime metrics without mutating state.",
        parameters_schema={
            "type": "object",
            "properties": {
                "metric_type": {"type": "string", "enum": ["all", "cpu", "memory", "uptime"], "maxLength": 16}
            },
            "required": ["metric_type"]
        },
        permissions=[
            ToolPermission(scope=PermissionScope.READ, resource_patterns=["system/telemetry"], data_classification=DataClassification.INTERNAL)
        ]
    )

    tool2 = ToolDefinition(
        name="lookup_weather",
        description="Fetches current weather conditions for a specified city name.",
        parameters_schema={
            "type": "object",
            "properties": {
                "city": {"type": "string", "maxLength": 64, "pattern": "^[a-zA-Z\\s\\-]+$"}
            },
            "required": ["city"]
        },
        permissions=[
            ToolPermission(scope=PermissionScope.READ, resource_patterns=["weather/*"], data_classification=DataClassification.PUBLIC)
        ]
    )

    adapter.register_tool(tool1, get_system_health_handler)
    adapter.register_tool(tool2, lookup_weather_handler)
    return adapter


if __name__ == "__main__":
    adapter = create_secure_adapter()
    print(f"Secure MCP Adapter initialized with tools: {list(adapter.tools_registry.keys())}")
