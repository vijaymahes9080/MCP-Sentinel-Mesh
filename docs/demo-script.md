# Live Demonstration Script: MCP Sentinel Mesh

Follow these steps to conduct an interactive 5-minute demonstration of MCP Sentinel Mesh:

---

## Step 1: Static Manifest Scanning & SARIF Output
Demonstrate deterministic detection of poisoned tool docstrings and excessive permissions:
```bash
# Scan vulnerable MCP server manifest
python sentinel.py scan mcp-samples/manifests/vulnerable_mcp.json --format markdown

# Show SARIF generation for GitHub Code Scanning
python sentinel.py scan mcp-samples/manifests/vulnerable_mcp.json --format sarif | head -n 30
```
*Key Talking Point: "Notice how Sentinel immediately catches the prompt injection hidden inside `read_file_safe` without invoking an LLM."*

---

## Step 2: n8n Workflow Security Audit
Demonstrate static graph inspection of an exported n8n workflow:
```bash
python sentinel.py scan n8n-samples/vulnerable_crm_sync.json --format markdown
```
*Key Talking Point: "Sentinel flags unauthenticated webhooks, dangerous code nodes accessing `process.env`, and internal SSRF to 127.0.0.1."*

---

## Step 3: Runtime Mediation & Output Redaction
Launch the proxy and demonstrate policy enforcement:
```bash
# Start proxy in terminal 1
uvicorn proxy.server:app --port 8000
```
In terminal 2, execute a tool call containing path traversal:
```bash
curl -X POST http://localhost:8000/proxy/tool-call \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "read_file_safe", "arguments": {"filepath": "../../etc/shadow"}}'
```
*Outcome: BLOCKED with "Path traversal pattern detected in tool arguments."*

Now execute a destructive call:
```bash
curl -X POST http://localhost:8000/proxy/tool-call \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "drop_database_table", "arguments": {"table_name": "users", "confirm_purge": true}}'
```
*Outcome: PENDING_APPROVAL with unique Approval Request ID.*

---

## Step 4: React Security Operations Dashboard
Open `http://localhost:5173` to explore:
1. Overview KPI cards & security posture score.
2. Tool Inventory with parameter schemas.
3. Interactive Approvals Queue (click "Authorize & Execute" or "Deny & Block").
4. Real-time Audit Ledger with SHA-256 chain verification badge.
5. Language toggle (switch smoothly between English and தமிழ்).
