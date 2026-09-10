# MCP Integration & Adapter Guide

## 1. Overview
MCP Sentinel Mesh connects to downstream Model Context Protocol (MCP) servers via protocol adapters. The adapter layer isolates execution, finger-prints tool schemas, enforces invocation timeouts, and tracks tool versions.

---

## 2. Tool Schema Fingerprinting
To prevent tool poisoning or runtime schema alteration, Sentinel computes a canonical SHA-256 fingerprint for every registered tool schema:
```python
import hashlib, json
canonical_json = json.dumps(tool.parameters_schema, sort_keys=True)
schema_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
```
If a downstream server dynamically modifies parameter types or descriptions after registration, the proxy detects the divergence and blocks invocations.

---

## 3. Sample Synthetic Servers
The repository includes three synthetic mock servers for evaluation:
1. `mcp-samples/servers/secure_server.py`: Safe read-only telemetry (`get_system_health`, `lookup_weather`).
2. `mcp-samples/servers/vulnerable_server.py`: Poisoned descriptions with embedded prompt injection strings (`read_file_safe`, `fetch_remote_resource`).
3. `mcp-samples/servers/high_risk_server.py`: Administrative mutating tools requiring human approval (`execute_shell_command`, `drop_database_table`).
